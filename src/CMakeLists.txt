add_library(nosql_db STATIC
    storage/log_storage.cpp
    storage/btree_index.cpp
)

target_link_libraries(nosql_db
    fmt::fmt
    spdlog::spdlog
)

add_executable(nosql_db_main
    main.cpp
)

target_link_libraries(nosql_db_main
    nosql_db
)