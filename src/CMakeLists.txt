
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
    set(WINSOCK2 ws2_32)
    set(CRYPT32 crypt32)
elseif (NOT APPLE)
    find_library(LIBRT rt)
endif ()


set(USE_CRYPTO_OPENSSL 1)
set(UVW_SOURCE
    uvw/async.cpp
    uvw/check.cpp
    uvw/dns.cpp
    uvw/emitter.cpp
    uvw/fs.cpp
    uvw/fs_event.cpp
    uvw/fs_poll.cpp
    uvw/idle.cpp
    uvw/lib.cpp
    uvw/loop.cpp
    uvw/pipe.cpp
    uvw/poll.cpp
    uvw/prepare.cpp
    uvw/process.cpp
    uvw/signal.cpp
    uvw/stream.cpp
    uvw/tcp.cpp
    uvw/thread.cpp
    uvw/timer.cpp
    uvw/tty.cpp
    uvw/util.cpp
    uvw/work.cpp
    uvw/udp.cpp
    )
add_library(UVW_LIB STATIC ${UVW_SOURCE})
target_link_libraries(UVW_LIB ${LibUV_LIBRARIES})
target_compile_definitions(UVW_LIB PUBLIC UVW_AS_LIB)

set(SOURCE_FILES_LOCAL
        ssrutils.h
        obfs/crc32.h
        obfs/auth.c
        obfs/auth.h
        obfs/obfs.c
        obfs/obfs.h
        obfs/base64.h
        obfs/auth_chain.h
        obfs/auth_chain.c
        obfs/http_simple.h
        obfs/obfsutil.c
        obfs/base64.c
        obfs/tls1.2_ticket.h
        obfs/http_simple.c
        obfs/tls1.2_ticket.c
        obfs/crc32.c
        obfs/obfsutil.h
        ObfsClass.hpp
        ObfsClass.cpp
        local_uv.cpp
        Buffer.hpp
        encrypt.c
        ConnectionContext.hpp
        sockaddr_universal.h
        uvw_single.hpp
        ConnectionContext.cpp
        encrypt.h
        cache.h
        ssrutils.c
        shadowsocksr.h
        CipherEnv.hpp
        sockaddr_universal.c
        CipherEnv.cpp
        uthash.h
        Buffer.cpp
        cache.c
        NetUtils.hpp
        NetUtils.cpp
        UDPConnectionContext.cpp UDPConnectionContext.hpp UDPRelay.cpp UDPRelay.hpp)
if (SSR_UVW_WITH_QT)
    message("find Qt5")
    find_package(Qt5 COMPONENTS Core REQUIRED)
    qt5_wrap_cpp(ssr_thread_moc SSRThread.hpp)
    set(SOURCE_FILES_LOCAL_QT
            ${ssr_thread_moc}
            SSRThread.cpp
            qt_ui_log.cpp
            ${SOURCE_FILES_LOCAL})
    add_library(${PROJECT_NAME}-qt STATIC ${SOURCE_FILES_LOCAL_QT})
    target_compile_definitions(${PROJECT_NAME}-qt PUBLIC SSR_UVW_WITH_QT UVW_AS_LIB)
    set_target_properties(${PROJECT_NAME}-qt PROPERTIES POSITION_INDEPENDENT_CODE 1)
    add_library(shadowsocksr::uvw::qt ALIAS ${PROJECT_NAME}-qt)
endif ()
include_directories(${LibUV_INCLUDE_DIR})
include_directories(${libsodium_include_dirs})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES_LOCAL})
add_library(shadowsocksr::uvw ALIAS ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_compile_definitions(${PROJECT_NAME} PUBLIC UVW_AS_LIB)
set(
        COMMON_LINK_LIBS
        ${LIBRT}
        ${LibUV_LIBRARIES}
        ${WINSOCK2}
        ${CRYPT32}
        UVW_LIB
)

set(ssr_crypto
        ${LIBCRYPTO}
        ${sodium_LIBRARIES}
        )


if (SSR_UVW_WITH_QT)
    target_link_libraries(${PROJECT_NAME}-qt Qt5::Core
            ${COMMON_LINK_LIBS} ${ssr_crypto}
            )
endif ()
target_include_directories(
        ${PROJECT_NAME}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
 )

target_link_libraries(${PROJECT_NAME}
        ${ssr_crypto} ${COMMON_LINK_LIBS}
        )
if(NOT WIN32)
    set(SSR_LOCAL_SOURCE ssr_local.cpp)
else()
    set(SSR_LOCAL_SOURCE ssr_local.cpp win/getopt.c)
endif()
add_executable(ssr-local ${SOURCE_FILES_LOCAL} ${SSR_LOCAL_SOURCE})
    target_compile_definitions(ssr-local PUBLIC UVW_AS_LIB)
    target_link_libraries(ssr-local shadowsocksr::uvw)
