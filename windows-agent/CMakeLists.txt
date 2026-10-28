cmake_minimum_required(VERSION 3.24)
project(SentinelACAgent VERSION 2.4.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(SentinelAgentService
    src/SentinelAgentService.cpp
)

if(WIN32)
    target_compile_definitions(SentinelAgentService PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    target_link_libraries(SentinelAgentService PRIVATE
        wintrust
        bcrypt
        crypt32
        winhttp
        psapi
        advapi32
    )
endif()
