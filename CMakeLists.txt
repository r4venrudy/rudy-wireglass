cmake_minimum_required(VERSION 3.20)
project(rudy_wireglass VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(wireglass_core STATIC
    src/wireglass.c
    src/capture.c
    src/packet.c
    src/report.c
)
target_include_directories(wireglass_core
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(MSVC)
    target_compile_options(wireglass_core PRIVATE /W4)
else()
    target_compile_options(wireglass_core PRIVATE -Wall -Wextra -Wpedantic)
    if(UNIX)
        target_link_libraries(wireglass_core PUBLIC m)
    endif()
endif()

add_executable(wireglass src/main.c)
target_link_libraries(wireglass PRIVATE wireglass_core)
if(MSVC)
    target_compile_options(wireglass PRIVATE /W4)
else()
    target_compile_options(wireglass PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(wireglass_tests tests/test_wireglass.c)
    target_link_libraries(wireglass_tests PRIVATE wireglass_core)
    if(MSVC)
        target_compile_options(wireglass_tests PRIVATE /W4)
    else()
        target_compile_options(wireglass_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME wireglass-tests COMMAND wireglass_tests)
    add_test(NAME refuse-input-overwrite
        COMMAND wireglass scan
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/demo.pcap"
            --output "${CMAKE_CURRENT_SOURCE_DIR}/examples/demo.pcap"
    )
    set_tests_properties(refuse-input-overwrite PROPERTIES WILL_FAIL TRUE)
endif()

include(GNUInstallDirs)
install(TARGETS wireglass RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/wireglass.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
