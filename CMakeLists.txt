# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011-2015, RedJack, LLC.
# All rights reserved.
#
# Please see the COPYING file in this distribution for license details.
# ----------------------------------------------------------------------

cmake_minimum_required(VERSION 3.2)
set(PROJECT_NAME shadowsocksr-uvw)
project(${PROJECT_NAME})

set(VERSION 0.0.1)
# Detect linux
if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()
if(WIN32)
      if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
          if(CMAKE_CL_64)
            include(${CMAKE_SOURCE_DIR}/libs/x64-windows-static/scripts/buildsystems/vcpkg.cmake)
          else()
            include(${CMAKE_SOURCE_DIR}/libs/x86-windows-static/scripts/buildsystems/vcpkg.cmake)
          endif()
      endif()
endif()

set(with_crypto_library "openssl" CACHE STRING "build with the given crypto library, TYPE=openssl|polarssl|mbedtls default=openssl")
set(SSR_UVW_WITH_QT 1 CACHE BOOL "build with qt")


include ( cmake/dist.cmake )
include ( configure )
configure_file ( ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )


include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

add_subdirectory(src)
