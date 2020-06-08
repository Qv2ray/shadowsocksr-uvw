#include "ssrutils.h"
#include <cstdarg>
#include <cstring>

#ifdef SSR_UVW_WITH_QT
#include "qt_ui_log.h"
#endif

namespace
{
constexpr int SSR_LOG_BUFFER_SIZE = 1024;
void _ssr_log_write(char* msg)
{
#ifdef SSR_UVW_WITH_QT
    qt_ui_log(msg);
#else
    strcat(msg, "\n");
    fprintf(stderr, "%s", msg);
    fflush(stderr);
#endif
}
}

void ssr_log_print(const char* fmt, ...)
{
    va_list ap;
    char buf[SSR_LOG_BUFFER_SIZE];
    va_start(ap, fmt);
    vsnprintf(buf, SSR_LOG_BUFFER_SIZE, fmt, ap);
    va_end(ap);
    return _ssr_log_write(buf);
}
