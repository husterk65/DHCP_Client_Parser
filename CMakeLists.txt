cmake_minimum_required(VERSION 3.10)
project(DHCPClientParserProject)

add_subdirectory(lib)

add_executable(main_exec src/main.c)

target_link_libraries(main_exec PRIVATE DhcpClientParser) 

