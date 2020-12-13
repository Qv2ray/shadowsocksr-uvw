
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
    set(WINSOCK2 ws2_32)
    set(CRYPT32 crypt32)
elseif (NOT APPLE)
    find_library(LIBRT rt)
endif ()


set(USE_CRYPTO_OPENSSL 1)

set(SOURCE_FILES_LOCAL
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
        TCPRelay.hpp
        UDPConnectionContext.cpp UDPConnectionContext.hpp UDPRelay.cpp UDPRelay.hpp)
add_library(shadowsocksr-uvw-common OBJECT ${SOURCE_FILES_LOCAL})
target_compile_definitions(shadowsocksr-uvw-common PUBLIC UVW_AS_LIB)
if (SSR_UVW_WITH_QT)
    if(NOT QV_QT_LIBNAME)
        set(QV_QT_LIBNAME Qt5)
    endif()
    message("find ${QV_QT_LIBNAME}")
    find_package(${QV_QT_LIBNAME} COMPONENTS Core REQUIRED)
    qt_wrap_cpp(ssr_thread_moc SSRThread.hpp)
    set(SOURCE_FILES_LOCAL_QT
            ${ssr_thread_moc}
            SSRThread.cpp
            qt_ui_log.cpp
            ssr_log_utils.cpp
            local_uv.cpp
            #local_uv.cpp uses macro SSR_UVW_WITH_QT,so it's not part of shadowsocksr-uvw-common
            )
    add_library(${PROJECT_NAME}-qt STATIC ${SOURCE_FILES_LOCAL_QT} $<TARGET_OBJECTS:shadowsocksr-uvw-common>)
    target_compile_definitions(${PROJECT_NAME}-qt PUBLIC SSR_UVW_WITH_QT UVW_AS_LIB)
    set_target_properties(${PROJECT_NAME}-qt PROPERTIES POSITION_INDEPENDENT_CODE 1)
    add_library(shadowsocksr::uvw::qt ALIAS ${PROJECT_NAME}-qt)
endif ()
include_directories(${LibUV_INCLUDE_DIR})
include_directories(${libsodium_include_dirs})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(${PROJECT_NAME} STATIC local_uv.cpp ssr_log_utils.cpp $<TARGET_OBJECTS:shadowsocksr-uvw-common>)
#local_uv.cpp uses macro SSR_UVW_WITH_QT,so it's not part of shadowsocksr-uvw-common
add_library(shadowsocksr::uvw ALIAS ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_compile_definitions(${PROJECT_NAME} PUBLIC UVW_AS_LIB)
set(
        COMMON_LINK_LIBS
        ${LIBRT}
        ${LibUV_LIBRARIES}
        ${WINSOCK2}
        ${CRYPT32}
)

set(ssr_crypto
        ${LIBCRYPTO}
        ${sodium_LIBRARIES}
        )

if(WIN32)
    target_link_libraries(shadowsocksr-uvw-common 
        ${COMMON_LINK_LIBS} ${ssr_crypto})
endif()

if (SSR_UVW_WITH_QT)
    target_link_libraries(${PROJECT_NAME}-qt ${QV_QT_LIBNAME}::Core
            ${COMMON_LINK_LIBS} ${ssr_crypto}
            )
endif ()
target_include_directories(
        ${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(${PROJECT_NAME}
        ${COMMON_LINK_LIBS} ${ssr_crypto}
        )
if(NOT WIN32)
    set(SSR_LOCAL_SOURCE ssr_local.cpp ssr_log_utils.cpp)
else()
    set(SSR_LOCAL_SOURCE ssr_local.cpp win/getopt.c ssr_log_utils.cpp)
endif()
add_executable(ssr-local ${SSR_LOCAL_SOURCE})
target_compile_definitions(ssr-local PUBLIC UVW_AS_LIB)
target_link_libraries(ssr-local shadowsocksr::uvw)
install(TARGETS ssr-local RUNTIME DESTINATION bin)
