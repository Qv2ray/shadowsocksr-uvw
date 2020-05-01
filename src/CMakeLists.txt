
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
        catch2.hpp
        sockaddr_universal.c
        CipherEnv.cpp
        uthash.h
        Buffer.cpp
        cache.c
        UDPConnectionContext.cpp UDPConnectionContext.hpp UDPRelay.cpp UDPRelay.hpp)
if (SSR_UVW_WITH_QT)
    message("find Qt5")
    find_package(Qt5 COMPONENTS Core REQUIRED)
    qt5_wrap_cpp(ssr_thread_moc SSRThread.hpp)
    set(SOURCE_FILES_LOCAL_QT
            ${ssr_thread_moc}
            ${SOURCE_FILES_LOCAL})
    add_library(${PROJECT_NAME}-qt STATIC ${SOURCE_FILES_LOCAL_QT})
    target_compile_definitions(${PROJECT_NAME}-qt PUBLIC -DSSR_UVW_WITH_QT)
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


if (SSR_UVW_WITH_QT)
    target_link_libraries(${PROJECT_NAME}-qt Qt5::Core
            ${COMMON_LINK_LIBS} ${ssr_crypto}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        ${ssr_crypto} ${COMMON_LINK_LIBS}
        )
if(NOT WIN32)
    add_executable(ssr-local ${SOURCE_FILES_LOCAL} ssr_local.cpp)
    target_link_libraries(ssr-local shadowsocksr::uvw)
endif()