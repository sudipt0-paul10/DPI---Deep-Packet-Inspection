# Each test file is a standalone executable; CTest reports one result per file.
# No external test framework - see test_support.h.

set(SAMPLE_PCAP ${CMAKE_SOURCE_DIR}/data/test_dpi.pcap)

# Unit tests that link only the parsing core.
foreach(test_name test_packet_parser test_sni_extractor test_flow_affinity)
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE dpi_core dpi_warnings)
    target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Rule handling lives in the pipeline library.
add_executable(test_rule_manager test_rule_manager.cpp)
target_link_libraries(test_rule_manager PRIVATE dpi_pipeline dpi_warnings)
target_include_directories(test_rule_manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_rule_manager COMMAND test_rule_manager)

# End-to-end test: drives the real multithreaded engine over the sample capture.
add_executable(test_pipeline test_pipeline.cpp)
target_link_libraries(test_pipeline PRIVATE dpi_pipeline dpi_warnings)
target_include_directories(test_pipeline PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_pipeline COMMAND test_pipeline ${SAMPLE_PCAP})

# Each test writes scratch files into its working directory.
set_tests_properties(test_rule_manager test_pipeline
    PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
