DEFINES += USE_CRYPTO_OPENSSL
DEFINES += SSR_UVW_WITH_QT

INCLUDEPATH += $$PWD/src

SOURCES += \
    $$PWD/src/Buffer.cpp \
    $$PWD/src/CipherEnv.cpp \
    $$PWD/src/ConnectionContext.cpp \
    $$PWD/src/ObfsClass.cpp \
    $$PWD/src/SSRThread.cpp \
    $$PWD/src/cache.c \
    $$PWD/src/encrypt.c \
    $$PWD/src/local_uv.cpp \
    $$PWD/src/obfs/auth.c \
    $$PWD/src/obfs/auth_chain.c \
    $$PWD/src/obfs/base64.c \
    $$PWD/src/obfs/crc32.c \
    $$PWD/src/obfs/http_simple.c \
    $$PWD/src/obfs/obfs.c \
    $$PWD/src/obfs/obfsutil.c \
    $$PWD/src/obfs/tls1.2_ticket.c \
    $$PWD/src/qt_ui_log.cpp \
    $$PWD/src/sockaddr_universal.c \
    $$PWD/src/ssrutils.c

HEADERS += \
    $$PWD/src/Buffer.hpp \
    $$PWD/src/CipherEnv.hpp \
    $$PWD/src/ConnectionContext.hpp \
    $$PWD/src/LogHelper.h \
    $$PWD/src/ObfsClass.hpp \
    $$PWD/src/SSRThread.hpp \
    $$PWD/src/cache.h \
    $$PWD/src/catch2.hpp \
    $$PWD/src/encrypt.h \
    $$PWD/src/obfs/auth.h \
    $$PWD/src/obfs/auth_chain.h \
    $$PWD/src/obfs/base64.h \
    $$PWD/src/obfs/crc32.h \
    $$PWD/src/obfs/http_simple.h \
    $$PWD/src/obfs/obfs.h \
    $$PWD/src/obfs/obfsutil.h \
    $$PWD/src/obfs/tls1.2_ticket.h \
    $$PWD/src/qt_ui_log.h \
    $$PWD/src/shadowsocks.h \
    $$PWD/src/sockaddr_universal.h \
    $$PWD/src/ssrutils.h \
    $$PWD/src/uthash.h \
    $$PWD/src/uvw_single.hpp
