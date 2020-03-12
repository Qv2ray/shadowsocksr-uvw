# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011-2015, RedJack, LLC.
# All rights reserved.
#
# Please see the COPYING file in this distribution for license details.
# ----------------------------------------------------------------------

cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME shadowsocks-libev)
project(${PROJECT_NAME})

set(VERSION 0.0.1)


set(with_crypto_library "openssl" CACHE STRING "build with the given crypto library, TYPE=openssl|polarssl|mbedtls default=openssl")
set(SSR_UVW_WITH_QT 1 CACHE BOOL "build with qt")


include ( cmake/dist.cmake )
include ( configure )
configure_file ( ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )


include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

add_subdirectory(src)
