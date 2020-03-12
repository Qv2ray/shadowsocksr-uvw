
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core REQUIRED)
set(USE_CRYPTO_OPENSSL 1)
set(CMAKE_AUTOMOC ON)
set(SOURCE_FILES_LOCAL
utils.h
obfs/crc32.h
obfs/auth.c
obfs/auth.h
obfs/obfs.c
obfs/obfs.h
obfs/base64.h
obfs/auth_chain.h
obfs/auth_chain.c
obfs/verify.c
obfs/http_simple.h
obfs/obfsutil.c
obfs/base64.c
obfs/tls1.2_ticket.h
obfs/verify.h
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
common.h
encrypt.h
cache.h
SSRThread.cpp
utils.c
shadowsocks.h
CipherEnv.hpp
SSRThread.hpp
catch2.hpp
sockaddr_universal.c
CipherEnv.cpp
uthash.h
Buffer.cpp
cache.c
)
include_directories(${libsodium_include_dirs})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(libshadowsocksr-libuv ${SOURCE_FILES_LOCAL})

target_compile_definitions(libshadowsocksr-libuv
        PRIVATE MODULE_LOCAL LIB_ONLY
        )


set (ss_lib_net
        ${LIBCRYPTO}
        sodium
        uv
	Qt5::Core
        )


target_link_libraries(libshadowsocksr-libuv
        ${ss_lib_net}
)
