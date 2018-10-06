cmake_minimum_required(VERSION 2.6)
set(LIBNLQ_VERSION_STRING 0.0.1)
set(LIBNLQ_VERSION_MAJOR 0)
add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(HEADERS_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/include)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

set(LIBNLQ_SOURCES nlq.c nlq_process_msg.c nlq_client.c nlq_ioctl.c nlq_proc.c)
add_library(nlq SHARED ${LIBNLQ_SOURCES})

set_target_properties(nlq PROPERTIES VERSION ${LIBNLQ_VERSION_STRING}
        SOVERSION ${LIBNLQ_VERSION_MAJOR})

install(TARGETS nlq LIBRARY DESTINATION lib)
install(FILES libnlq.h DESTINATION ${HEADERS_INSTALL_PATH})

