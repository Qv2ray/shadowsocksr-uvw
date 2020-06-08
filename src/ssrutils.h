/*
 * ssrutils.h - Misc utilities
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _SSR_UTILS_H
#define _SSR_UTILS_H

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/opensslv.h>
#define USING_CRYPTO OPENSSL_VERSION_TEXT

#elif defined(USE_CRYPTO_POLARSSL)
#include <polarssl/version.h>
#define USING_CRYPTO POLARSSL_VERSION_STRING_FULL

#elif defined(USE_CRYPTO_MBEDTLS)
#include <mbedtls/version.h>
#define USING_CRYPTO MBEDTLS_VERSION_STRING_FULL

#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct tm* ssr_safe_localtime(time_t* t, struct tm* tp);
#ifdef ANDROID

#include <android/log.h>

#define USE_TTY()
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "shadowsocks", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "shadowsocks", __VA_ARGS__))

#else // ANDROID
void ssr_log_print(const char* fmt,...);
extern int use_tty;
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define LOGI(format, ...)                                                                        \
    do {                                                                                         \
            time_t now = time(NULL);                                                             \
            struct tm tp;                                                                        \
            char timestr[20];                                                                    \
            strftime(timestr, 20, TIME_FORMAT, ssr_safe_localtime(&now, &tp));                   \
            if (use_tty) {                                                                       \
                ssr_log_print("\e[01;32m %s INFO: \e[0m" format, timestr, ##__VA_ARGS__); \
            } else {                                                                             \
                ssr_log_print(" %s INFO: " format , timestr, ##__VA_ARGS__);               \
            }                                                                                    \
    } while (0)

#define LOGE(format, ...)                                                                         \
    do {                                                                                          \
            time_t now = time(NULL);                                                              \
            struct tm tp;                                                                         \
            char timestr[20];                                                                     \
            strftime(timestr, 20, TIME_FORMAT, ssr_safe_localtime(&now, &tp));                    \
            if (use_tty) {                                                                        \
                ssr_log_print( "\e[01;35m %s ERROR: \e[0m" format, timestr, ##__VA_ARGS__); \
            } else {                                                                              \
                ssr_log_print( " %s ERROR: " format , timestr, ##__VA_ARGS__);               \
            }                                                                                     \
    } while (0)
#if defined(_WIN32)
#define USE_TTY()
#else
#define USE_TTY()                        \
    do {                                 \
        use_tty = isatty(STDERR_FILENO); \
    } while (0)
#endif
#endif // ANDROID

void FATAL(const char* msg);

void* ss_malloc(size_t size);
void* ss_realloc(void* ptr, size_t new_size);

#define ss_free(ptr) \
    do {             \
        free(ptr);   \
        ptr = NULL;  \
    } while (0)

#ifdef __cplusplus
}
#endif
#endif // _UTILS_H
