# Build args
if(USE_SYSTEM_LIBUV)
    if(NOT WIN32)
        find_package(LibUV REQUIRED)
    else()
        find_package(unofficial-libuv CONFIG REQUIRED)
        set(${LibUV_LIBRARIES} unofficial::libuv::libuv)
    endif()
endif()

if (${WITH_CRYPTO_LIBRARY} STREQUAL "openssl")
    find_package(OpenSSL REQUIRED)
    if(USE_SYSTEM_SODIUM)
        if(NOT WIN32)
            find_package(Sodium REQUIRED)
        else()
            find_package(unofficial-sodium CONFIG REQUIRED)
            set(${sodium_LIBRARIES} unofficial-sodium::sodium)
        endif()
    endif()
    set(USE_CRYPTO_OPENSSL 1)
    if(NOT WIN32)
        set(LIBCRYPTO
            ${OPENSSL_CRYPTO_LIBRARY})
    else()
        set(LIBCRYPTO OpenSSL::SSL OpenSSL::Crypto)
    endif()
    message("found open ssl")
    include_directories(${OPENSSL_INCLUDE_DIR})

    list ( APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})

elseif(${with_crypto_library} STREQUAL "polarssl")
    find_package(polarssl REQUIRED)
    set(USE_CRYPTO_POLARSSL 1)
elseif(${with_crypto_library} STREQUAL "mbedtls")
    find_package(mbedtls REQUIRED)
    set(USE_CRYPTO_MBEDTLS 1)
endif()



# Platform checks
include ( CheckFunctionExists )
include ( CheckIncludeFiles )
include ( CheckSymbolExists )
include ( CheckCSourceCompiles )
include ( CheckTypeSize )
include ( CheckSTDC )

check_include_files ( inttypes.h HAVE_INTTYPES_H )

ADD_DEFINITIONS(-DHAVE_CONFIG_H)
