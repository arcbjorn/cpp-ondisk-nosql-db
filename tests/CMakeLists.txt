add_executable(tests
    test_log_storage.cpp
    test_main.cpp
)

target_link_libraries(tests
    nosql_db
    Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(tests)