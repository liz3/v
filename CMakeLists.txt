cmake_minimum_required(VERSION 3.16)
project(v)
option(V_BUILD_EXAMPLE "Build Example Executable" ON)

set(V_SOURCES src/v.c src/aes.c src/v_util.c)

add_library(v SHARED ${V_SOURCES})
set_property(TARGET v PROPERTY C_STANDARD 11)

if(V_BUILD_EXAMPLE)
    add_executable(v-example example/main.c)
    target_link_libraries(v-example v)
endif()

target_compile_options(v PRIVATE "-g")
set(CMAKE_C_FLAGS "-g")