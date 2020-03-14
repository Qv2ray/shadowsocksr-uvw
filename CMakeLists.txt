# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011-2015, RedJack, LLC.
# All rights reserved.
#
# Please see the COPYING file in this distribution for license details.
# ----------------------------------------------------------------------

cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME shadowsocksr-uvw)
project(${PROJECT_NAME})

set(VERSION 0.0.1)
# Detect linux
if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

set(with_crypto_library "openssl" CACHE STRING "build with the given crypto library, TYPE=openssl|polarssl|mbedtls default=openssl")
set(SSR_UVW_WITH_QT 1 CACHE BOOL "build with qt")
set(PROJECT_CMAKE_IN ${PROJECT_SOURCE_DIR}/cmake/in)
set(PROJECT_DEPS_DIR ${PROJECT_SOURCE_DIR}/deps)
set(LIBUV_DEPS_DIR ${PROJECT_DEPS_DIR}/libuv)
configure_file(${PROJECT_CMAKE_IN}/deps.in ${PROJECT_DEPS_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . WORKING_DIRECTORY ${PROJECT_DEPS_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build . WORKING_DIRECTORY ${PROJECT_DEPS_DIR})
add_subdirectory(${LIBUV_DEPS_DIR})
include_directories(${LIBUV_DEPS_DIR}/include)


include ( cmake/dist.cmake )
include ( configure )
configure_file ( ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )


include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

add_subdirectory(src)
