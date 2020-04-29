/*
 * utils.c - Misc utilities
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssrutils.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define INT_DIGITS 19 /* enough for 64 bit integer */

#ifdef LIB_ONLY
FILE* logfile;
#endif

#ifdef HAS_SYSLOG
int use_syslog = 0;
#endif

int use_tty = 1;

struct tm* ssr_safe_localtime(time_t* t, struct tm* tp)
{
#ifdef _WIN32
    //windows localtime is thread safe
    //https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/localtime-localtime32-localtime64?view=vs-2019
    return localtime(t);
#else
    return localtime_r(t, tp);
#endif
}

char* ss_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char* p = buf + INT_DIGITS + 1; /* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    } else { /* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

int ss_isnumeric(const char* s)
{
    if (!s || !*s)
        return 0;
    while (isdigit(*s))
        ++s;
    return *s == '\0';
}

char* ss_strndup(const char* s, size_t n)
{
    size_t len = strlen(s);
    char* ret;

    if (len <= n) {
        return strdup(s);
    }

    ret = ss_malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

char* ss_strdup(const char* s)
{
    if (!s) {
        return NULL;
    }

    return strdup(s);
}

void FATAL(const char* msg)
{
    LOGE("%s", msg);
    exit(-1);
}

void* ss_malloc(size_t size)
{
    void* tmp = malloc(size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

void* ss_realloc(void* ptr, size_t new_size)
{
    void* new = realloc(ptr, new_size);
    if (new == NULL) {
        free(ptr);
        ptr = NULL;
        exit(EXIT_FAILURE);
    }
    return new;
}
