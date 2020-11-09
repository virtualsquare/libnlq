cmake_minimum_required(VERSION 3.12)
project(libnlq
		VERSION 0.0.1
		DESCRIPTION "Netlink Queue Library"
		HOMEPAGE_URL "https://github.com/virtualsquare/libnlq"
		LANGUAGES C)

include(GNUInstallDirs)
add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(LIBNLQ_SOURCES nlq.c nlq_process_msg.c nlq_client.c nlq_ioctl.c nlq_proc.c)
add_library(nlq SHARED ${LIBNLQ_SOURCES})

set_target_properties(nlq PROPERTIES VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS nlq LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES libnlq.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
