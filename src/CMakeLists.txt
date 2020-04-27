
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
    set(WINSOCK2 ws2_32)
    set(CRYPT32 crypt32)
elseif (NOT APPLE)
    find_library(LIBRT rt)
endif ()

if (SSR_UVW_WITH_QT)
    message("find Qt5")
    add_definitions(-DSSR_UVW_WITH_QT)
    find_package(Qt5 COMPONENTS Core REQUIRED)
endif ()

set(USE_CRYPTO_OPENSSL 1)

if (SSR_UVW_WITH_QT)
    qt5_wrap_cpp(ssr_thread_moc SSRThread.hpp)
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
            qt_ui_log.h
            encrypt.c
            ConnectionContext.hpp
            sockaddr_universal.h
            uvw_single.hpp
            qt_ui_log.cpp
            ConnectionContext.cpp
            encrypt.h
            cache.h
            SSRThread.cpp
            ssrutils.c
            shadowsocksr.h
            CipherEnv.hpp
            SSRThread.hpp
            catch2.hpp
            sockaddr_universal.c
            CipherEnv.cpp
            uthash.h
            Buffer.cpp
            cache.c
            ${ssr_thread_moc}
            UDPConnectionContext.cpp UDPConnectionContext.hpp UDPRelay.cpp UDPRelay.hpp)
else ()
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

set(ss_lib_net
        ${LIBCRYPTO}
        ${sodium_LIBRARIES}
        )


if (SSR_UVW_WITH_QT)
    target_link_libraries(${PROJECT_NAME} Qt5::Core
            ${COMMON_LINK_LIBS}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        ${ss_lib_net} ${COMMON_LINK_LIBS}
        )
