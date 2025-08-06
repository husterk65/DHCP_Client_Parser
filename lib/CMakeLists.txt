add_library(DhcpClientParser STATIC
    dhcp_client.c
    dhcp_client.h
)

target_include_directories(DhcpClientParser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
