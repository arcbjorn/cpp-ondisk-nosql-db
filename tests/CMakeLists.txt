add_executable(tests
    test_log_storage.cpp
    test_btree_index.cpp
    test_api.cpp
    test_transactions.cpp
    test_lsm_tree.cpp
    test_query_engine.cpp
    test_binary_protocol.cpp
    test_network_metrics.cpp
    test_connection_pool.cpp
    test_binary_client.cpp
    test_streaming.cpp
    security_tests.cpp
    test_main.cpp
)

target_link_libraries(tests
    ishikura
    Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(tests)