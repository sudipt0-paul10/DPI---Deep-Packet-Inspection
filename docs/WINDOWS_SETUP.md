# Building on Windows

The project needs only **CMake ≥ 3.16** and a **C++17 compiler**. There are no
third-party libraries to install. Pick whichever toolchain below you already
have, or the first one if you have none.

- [Option 1: MinGW-w64 (quickest)](#option-1-mingw-w64-quickest)
- [Option 2: Visual Studio](#option-2-visual-studio)
- [Option 3: MSYS2](#option-3-msys2)
- [Option 4: WSL](#option-4-wsl)
- [Option 5: VS Code](#option-5-vs-code)
- [Running](#running)
- [Troubleshooting](#troubleshooting)

> **A C++17 compiler is genuinely required.** The code uses `std::optional`,
> structured bindings and `std::shared_mutex`. GCC 6 and earlier will fail with
> `fatal error: optional: No such file or directory`. Use GCC 7+, Clang 5+, or
> MSVC 2017 15.7+.

---

## Option 1: MinGW-w64 (quickest)

With [winget](https://learn.microsoft.com/windows/package-manager/winget/)
(bundled with Windows 10/11):

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT
winget install Kitware.CMake
```

Open a **new** terminal so the updated `PATH` takes effect, then:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Binaries land in `build\`.

## Option 2: Visual Studio

Install [Visual Studio](https://visualstudio.microsoft.com/downloads/)
(Community is fine) or the standalone Build Tools, and make sure you tick the
**"Desktop development with C++"** workload — without it there is no `cl.exe`,
only headers.

CMake ships with that workload. From a **Developer Command Prompt**:

```cmd
cmake -S . -B build
cmake --build build --config Release
```

Binaries land in `build\Release\`.

You can also use **File → Open → Folder** in Visual Studio, which detects
`CMakeLists.txt` and configures the project automatically.

## Option 3: MSYS2

```bash
# In the MSYS2 UCRT64 shell
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake
```

```bash
cmake -S . -B build -G "Ninja"
cmake --build build
```

## Option 4: WSL

```bash
wsl --install          # in PowerShell, if WSL is not set up yet
```

Then inside the Linux shell:

```bash
sudo apt update
sudo apt install build-essential cmake

cd /mnt/c/path/to/the/repo
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Option 5: VS Code

1. Install [VS Code](https://code.visualstudio.com/).
2. Install the **C/C++** and **CMake Tools** extensions.
3. Install a compiler — Option 1 or 2 above.
4. Open the repository folder. CMake Tools picks up `CMakeLists.txt`.
5. Choose a kit when prompted, then press **F7** to build.

---

## Running

From the build directory:

```powershell
.\dpi_engine.exe ..\data\test_dpi.pcap out.pcap
.\dpi_engine.exe ..\data\test_dpi.pcap out.pcap --block-app YouTube
.\dpi_engine.exe ..\data\test_dpi.pcap out.pcap --rules ..\examples\rules.conf
```

Run the test suite:

```powershell
cd build
ctest --output-on-failure
```

---

## Troubleshooting

**`'cmake' is not recognized`**
CMake is not on `PATH`. Open a new terminal after installing, or add its `bin`
directory (typically `C:\Program Files\CMake\bin`) to `PATH` yourself.

**`'g++' is not recognized`**
Same cause. WinLibs installs to
`%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs...\mingw64\bin`;
add it to `PATH` or use a fresh terminal.

**`fatal error: optional: No such file or directory`**
Your compiler predates C++17 — most often an old MinGW on `PATH` shadowing a
newer one. Check with `g++ --version`; you need 7 or later.

**`CMAKE_CXX_COMPILER not found` when using MinGW**
CMake defaulted to the Visual Studio generator. Pass the generator explicitly:
`-G "MinGW Makefiles"`.

**`The code execution cannot proceed because libstdc++-6.dll was not found`**
The MinGW `bin` directory is not on `PATH` at *run* time. Add it, or run from a
terminal where it is.

**`mingw32-make` not found**
Some MinGW distributions name it `mingw32-make.exe` rather than `make`. Use
`cmake --build build`, which invokes the right tool for you.

**Cannot open the output file**
The path must be writable and its directory must already exist. The engine does
not create directories.

**Build succeeds but nothing is classified**
Check you are pointing at a capture that actually contains TLS ClientHellos or
HTTP requests. `data\test_dpi.pcap` does; regenerate it with
`python scripts\generate_test_pcap.py` if needed.
