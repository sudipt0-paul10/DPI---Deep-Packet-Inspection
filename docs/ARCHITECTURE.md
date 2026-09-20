# Architecture

A walkthrough of how the engine works, from a raw byte in a PCAP file to a
blocking decision. The [README](../README.md) covers what the project does;
this document covers how and why.

- [Background: what a packet looks like](#background-what-a-packet-looks-like)
- [The five-tuple](#the-five-tuple)
- [Why SNI is visible at all](#why-sni-is-visible-at-all)
- [Layer 1: reading a PCAP file](#layer-1-reading-a-pcap-file)
- [Layer 2: parsing protocol headers](#layer-2-parsing-protocol-headers)
- [Layer 3: extracting the SNI](#layer-3-extracting-the-sni)
- [Layer 4: the multithreaded pipeline](#layer-4-the-multithreaded-pipeline)
- [The thread-safe queue](#the-thread-safe-queue)
- [Why flow affinity, and why not consistent hashing](#why-flow-affinity-and-why-not-consistent-hashing)
- [Shutdown and the drain barrier](#shutdown-and-the-drain-barrier)
- [Flow state and the TCP state machine](#flow-state-and-the-tcp-state-machine)
- [Rule evaluation](#rule-evaluation)
- [Where the concurrency bodies are buried](#where-the-concurrency-bodies-are-buried)

---

## Background: what a packet looks like

Every captured frame is headers nested inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IPv4 Header (20+ bytes, length given by IHL)                 │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20+ bytes, length given by data offset)      │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload — e.g. a TLS ClientHello carrying the SNI    │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

Two of those header lengths are variable, which is the first thing a parser has
to get right:

- IPv4 carries **IHL**, the header length in 32-bit words. Options push the
  transport header past the usual offset 34.
- TCP carries a **data offset** field, likewise in 32-bit words. Timestamps and
  SACK options make TCP headers longer than 20 bytes routinely.

Assuming fixed offsets works on synthetic captures and quietly mis-parses real
ones. [`packet_parser.cpp`](../src/core/packet_parser.cpp) reads both fields
and validates each against the remaining buffer before advancing.

## The five-tuple

A flow is identified by five values:

| Field | Example | Meaning |
|---|---|---|
| Source IP | 192.168.1.100 | who is sending |
| Destination IP | 142.250.185.206 | where it is going |
| Source port | 54321 | the sender's socket |
| Destination port | 443 | the service being reached |
| Protocol | TCP (6) | TCP or UDP |

Everything downstream depends on this. Packets sharing a five-tuple belong to
one conversation, so a decision made about one of them — "this flow is
YouTube, block it" — applies to all of them without re-inspecting each packet.

## Why SNI is visible at all

HTTPS is encrypted, so how can a hostname be read out of it?

Because the hostname is sent *before* encryption starts. A TLS session opens
with a ClientHello in cleartext, and it has to name the host so that a server
hosting many sites knows which certificate to present:

```
┌──────────┐                                  ┌──────────┐
│ Browser  │                                  │  Server  │
└────┬─────┘                                  └────┬─────┘
     │ ──── ClientHello ───────────────────────────►│
     │      SNI: www.youtube.com   ← cleartext      │
     │                                              │
     │ ◄─── ServerHello + certificate ───────────── │
     │ ──── key exchange ──────────────────────────►│
     │ ◄═══ encrypted application data ════════════►│
     │      opaque from here on                     │
```

So the engine reads exactly one thing from a TLS flow: the hostname in the
first packet. Nothing is decrypted, and nothing after the handshake is
readable. The practical consequence is that DPI of this kind sees *who you are
talking to*, never *what you are saying*.

(Encrypted ClientHello closes even this window. It is not handled here.)

## Layer 1: reading a PCAP file

[`pcap_reader.cpp`](../src/core/pcap_reader.cpp). A classic PCAP file is a
24-byte global header followed by repeating (16-byte record header, packet
bytes) pairs.

The magic number tells you the byte order:

- `0xa1b2c3d4` — same endianness as this machine, read fields directly.
- `0xd4c3b2a1` — opposite endianness, swap every multi-byte field.

The reader sanity-checks each record's `incl_len` against the file's snaplen
before allocating, so a corrupt length field cannot drive a huge allocation.

## Layer 2: parsing protocol headers

[`packet_parser.cpp`](../src/core/packet_parser.cpp) walks the layers in order,
and each step refuses to proceed if the remaining buffer is too short:

1. **Ethernet** — needs 14 bytes; reads the EtherType. Anything that is not
   `0x0800` (IPv4) stops here.
2. **IPv4** — needs 20 bytes; checks version 4, reads IHL, rejects IHL below
   the 20-byte minimum, reads protocol and addresses.
3. **TCP** — needs 20 bytes; reads ports, sequence and ack numbers, flags, and
   the data offset.
4. **UDP** — needs 8 bytes; reads ports.

Whatever is left after the transport header is the payload.
[`tests/test_packet_parser.cpp`](../tests/test_packet_parser.cpp) asserts that
truncated frames at each of these boundaries are rejected rather than
mis-parsed.

Byte-order conversion uses [`platform.h`](../include/platform.h) rather than
`<arpa/inet.h>` or winsock, which is why the project builds on Windows, Linux
and macOS with no conditional compilation.

## Layer 3: extracting the SNI

[`sni_extractor.cpp`](../src/core/sni_extractor.cpp). The ClientHello is a
chain of length-prefixed blocks, so extraction is a walk where every length
must be checked before it is trusted:

```
Byte  0      Content type = 0x16 (handshake)
Bytes 1-2    Record version
Bytes 3-4    Record length
─── handshake layer ───
Byte  5      Handshake type = 0x01 (ClientHello)
Bytes 6-8    Handshake length (24-bit)
─── ClientHello body ───
Bytes 9-10   Client version
Bytes 11-42  Random (32 bytes)
Byte  43     Session ID length  ──┐ variable
             Session ID          ─┘
             Cipher suites length (2 bytes) + cipher suites
             Compression methods length (1 byte) + methods
             Extensions length (2 bytes)
─── extensions, walked in a loop ───
             Extension type (2 bytes)
             Extension length (2 bytes)
             └─ type 0x0000 = server_name:
                   list length (2), name type (1) = 0x00,
                   name length (2), hostname bytes  ← the target
```

Every one of those variable-length hops is a chance to read past the end of the
buffer if the length is hostile or the packet is truncated. Each is bounds-
checked. The test suite feeds the extractor **every prefix** of a valid
ClientHello, from zero bytes to full length, to exercise all of those paths.

Two more extractors live alongside it:

- **HTTP `Host`** — case-insensitive scan for the header, stripping any `:port`.
- **DNS query name** — decodes the length-prefixed labels of the first question
  into a dotted name.

## Layer 4: the multithreaded pipeline

The single-threaded version of this program is a loop: read, parse, classify,
decide, write. The multithreaded version splits that loop into stages connected
by queues, so the stages run concurrently.

```
                 ┌──────────────────┐
                 │  Reader thread   │  read PCAP, parse headers,
                 │                  │  build the five-tuple
                 └────────┬─────────┘
                          │  hash % num_lbs
            ┌─────────────┴─────────────┐
            ▼                           ▼
     ┌─────────────┐             ┌─────────────┐
     │    LB 0     │             │    LB 1     │
     └──────┬──────┘             └──────┬──────┘
            │  hash % fps_per_lb        │
      ┌─────┴─────┐               ┌─────┴─────┐
      ▼           ▼               ▼           ▼
   ┌─────┐     ┌─────┐         ┌─────┐     ┌─────┐
   │ FP0 │     │ FP1 │         │ FP2 │     │ FP3 │   flow table each,
   └──┬──┘     └──┬──┘         └──┬──┘     └──┬──┘   no locking
      └───────────┴───────┬────────┴───────────┘
                          ▼
                 ┌──────────────────┐
                 │  Writer thread   │  append forwarded packets
                 └──────────────────┘
```

Why two levels rather than one? A single dispatcher hashing directly to eight
workers would be one thread doing every hash and every enqueue — a serial
bottleneck in front of a parallel stage. Splitting it lets the balancing work
itself run in parallel. At the scale this project runs at, the reader is the
real bottleneck either way; the two-level shape is there because it is how
production packet-processing pipelines are organised, and it is what makes the
design worth studying.

**Where the work actually is:** the fast-path workers. Per packet, a worker
looks up the flow, updates TCP state, may parse a ClientHello, and evaluates
rules. That is the expensive part, and it is the part that runs N-way parallel.

## The thread-safe queue

[`thread_safe_queue.h`](../include/thread_safe_queue.h). A bounded blocking
queue: one mutex, two condition variables.

```cpp
void push(T item) {
    std::unique_lock<std::mutex> lock(mutex_);
    not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
    if (shutdown_) return;
    queue_.push(std::move(item));
    not_empty_.notify_one();
}

std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!not_empty_.wait_for(lock, timeout,
                             [this] { return !queue_.empty() || shutdown_; })) {
        return std::nullopt;       // timed out; caller re-checks its stop flag
    }
    if (queue_.empty()) return std::nullopt;
    T item = std::move(queue_.front());
    queue_.pop();
    not_full_.notify_one();
    return item;
}
```

Three properties matter:

- **Bounded.** `max_size_` means a fast reader cannot balloon memory ahead of
  slow workers. A full queue blocks the producer — backpressure, not loss.
- **Condition variables, not spinning.** A waiting thread sleeps rather than
  burning a core.
- **Timed pop.** Workers wake periodically even with no traffic, so they can
  observe a stop flag and run flow-table maintenance.

## Why flow affinity, and why not consistent hashing

The dispatch rule is:

```cpp
worker = FiveTupleHash{}(tuple) % worker_count;
```

Because the hash depends only on the five-tuple, every packet of a flow lands
on the same worker, every time. That single property is what lets each worker
own its flow table with **no lock at all** on the hot path. Shared flow state
would mean a mutex or a sharded map on every packet; flow affinity removes the
question entirely.

It is worth being precise about the name, because the wrong one is a common
résumé overstatement:

| Scheme | What it does | Used here? |
|---|---|---|
| **Modulo hashing** | `hash % n`. Trivial; remapping is total when `n` changes. | **Yes** |
| Consistent hashing | Hash ring with virtual nodes; only ~`1/n` of keys move when a node joins or leaves. | No |
| Rendezvous hashing | Score every node per key, take the max; also minimal-disruption. | No |

Consistent hashing exists to solve a problem this engine does not have: nodes
joining and leaving at runtime. Worker count here is fixed when the engine
starts and never changes, so there is no remapping to minimise, and a hash ring
would add machinery for no benefit. `hash % n` is the correct choice — it just
is not consistent hashing, and calling it that would be wrong.

Two honest consequences:

- **The hash is direction-sensitive.** `hash(A→B) ≠ hash(B→A)`, so the two
  directions of a connection are separate flows, usually on different workers.
  The engine therefore does unidirectional flow tracking. Making it
  bidirectional means normalising the tuple (for instance, ordering the two
  endpoints canonically before hashing) so both directions produce one key.
- **It balances flows, not bytes.** One elephant flow still occupies exactly
  one worker.

## Shutdown and the drain barrier

Stopping a pipeline like this is where packets quietly go missing.

Each stage stops by setting a flag and shutting down its queue — and
`ThreadSafeQueue::push` on a shut-down queue **silently discards** the item.
So if the engine stops the workers while packets are still sitting in their
queues, those packets simply never appear in the output, with no error.

The original implementation waited a fixed `500ms` after the reader finished
and then tore everything down. On a small capture that looks fine; on a large
one it is silent data loss whose severity depends on machine load.

The engine now waits on actual counters instead:

```cpp
// Stage 1: every dispatched packet has been processed by a worker.
while (packets_completed_ < packets_dispatched_) { /* yield, with a timeout */ }

// Stage 2: every forwarded packet has been written to the output file.
while (packets_written_ < forwarded_packets_) { /* yield, with a timeout */ }

// Only now is it safe to stop threads.
```

The reader increments `dispatched` *before* enqueuing, so a packet can never be
seen as completed before it is known to exist. Workers increment `completed`
after handing the packet on, and the writer increments `written` after the
bytes hit the file. A 30-second cap turns a wedged pipeline into a warning
rather than a hang.

[`tests/test_pipeline.cpp`](../tests/test_pipeline.cpp) asserts that the output
PCAP holds exactly as many packets as the engine claims to have forwarded,
which is the property the drain exists to guarantee.

## Flow state and the TCP state machine

[`connection_tracker.cpp`](../src/engine/connection_tracker.cpp). Each worker
holds an `unordered_map<FiveTuple, Connection, FiveTupleHash>`.

```
NEW ──── SYN, SYN-ACK, ACK ────► ESTABLISHED
 │                                     │
 │         ClientHello / Host / DNS    │
 └──────────────┬──────────────────────┘
                ▼
          CLASSIFIED ──── matches a rule ────► BLOCKED
                │                                 │
                └──────── FIN / RST ──────────────┴──► CLOSED
```

- Classification is **sticky**: once a flow is classified, later packets reuse
  the result rather than re-parsing.
- `BLOCKED` is **sticky** too: the rule check happens once, and every
  subsequent packet of that flow is dropped immediately.
- Flows idle past the timeout are evicted, so a long run does not grow the
  table without bound.

The practical consequence of flows starting out unclassified: the TCP handshake
of a flow that will later be blocked is forwarded, because at that point the
engine does not yet know what the flow is. Blocking begins at the packet that
identifies it.

## Rule evaluation

[`rule_manager.cpp`](../src/engine/rule_manager.cpp). Checked in order —
source IP, destination port, application, domain — returning the reason for the
block so it can be logged.

The rule set is shared by every worker and guarded by a `std::shared_mutex`.
Workers only read, so they take shared locks and do not contend with each
other; the exclusive lock is taken only when rules are modified.

Domain rules come in two forms, and the difference is easy to trip over:

- `facebook.com` — **exact** match on that hostname alone.
- `*.facebook.com` — matches `www.facebook.com`, `cdn.facebook.com`, and the
  bare `facebook.com`.

Since real traffic almost always carries a subdomain in the SNI, the wildcard
form is usually what you want.

## Where the concurrency bodies are buried

Things this design has to get right, and where they are handled:

| Hazard | Handling |
|---|---|
| Concurrent flow-table access | Avoided entirely by flow affinity — each table has exactly one writer |
| Concurrent rule reads | `std::shared_mutex`, shared locks on the hot path |
| Concurrent output writes | Single writer thread; the file is touched by one thread only |
| Statistics updates | `std::atomic` counters |
| Per-worker dispatch counters | `std::atomic`, since the load balancer writes them while a reporting thread reads them |
| Packets lost at shutdown | The drain barrier above |
| Unbounded memory growth | Bounded queues that block producers |
| Reading past a packet's end | Length validation at every parsing hop, with truncation tests |

The remaining known weak points are listed honestly under
[Limitations](../README.md#limitations) in the README — most importantly that
output ordering is not preserved, and that no throughput measurements have been
taken, so none are claimed.
