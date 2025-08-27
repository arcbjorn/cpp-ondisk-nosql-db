add_library(ishikura STATIC
    storage/log_storage.cpp
    storage/btree_index.cpp
    storage/transaction.cpp
    storage/lsm_tree.cpp
    storage/storage_engine.cpp
    api/kv_controller.cpp
    query/query_engine.cpp
    network/binary_protocol.cpp
    network/binary_server.cpp
    network/connection_pool.cpp
    network/binary_client.cpp
    network/streaming.cpp
    network/metrics.cpp
    network/tls_server.cpp
    network/tls_client.cpp
    network/tls_utils.cpp
    security/auth.cpp
    security/audit.cpp
    security/api_key.cpp
)

target_link_libraries(ishikura
    fmt::fmt
    spdlog::spdlog
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_executable(ishikura_main
    main.cpp
)

target_link_libraries(ishikura_main
    ishikura
)

add_executable(ishikura_server
    api_server.cpp
)

target_link_libraries(ishikura_server
    ishikura
)

add_executable(ishikura_binary_server
    binary_server_main.cpp
)

target_link_libraries(ishikura_binary_server
    ishikura
)

add_executable(ishikura_client_demo
    client_demo.cpp
)

target_link_libraries(ishikura_client_demo
    ishikura
)

add_executable(ishikura_tls_server
    tls_server_main.cpp
)

target_link_libraries(ishikura_tls_server
    ishikura
)

add_executable(ishikura_tls_client
    tls_client_demo.cpp
)

target_link_libraries(ishikura_tls_client
    ishikura
)

add_executable(ishikura_api_key_manager
    api_key_manager.cpp
)

target_link_libraries(ishikura_api_key_manager
    ishikura
)