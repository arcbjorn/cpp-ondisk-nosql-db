add_library(nosql_db STATIC
    storage/log_storage.cpp
    storage/btree_index.cpp
    api/kv_controller.cpp
)

target_link_libraries(nosql_db
    fmt::fmt
    spdlog::spdlog
    httplib::httplib
    nlohmann_json::nlohmann_json
)

add_executable(nosql_db_main
    main.cpp
)

target_link_libraries(nosql_db_main
    nosql_db
)

add_executable(nosql_db_server
    api_server.cpp
)

target_link_libraries(nosql_db_server
    nosql_db
)