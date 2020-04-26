#include "qt_ui_log.h"

#include "SSRThread.hpp"
void qt_ui_log_info(const char* fmt, ...)
{
    auto ptr = dynamic_cast<SSRThread*>(QThread::currentThread());
    if (!ptr)
        return;
    QString str;
    va_list args1;
    va_start(args1, fmt);
    va_list args2;
    va_copy(args2, args1);
    std::vector<char> buf(1 + std::vsnprintf(nullptr, 0, fmt, args1));
    va_end(args1);
    std::vsnprintf(buf.data(), buf.size(), fmt, args2);
    va_end(args2);
    emit ptr->onSSRThreadLog(QString { buf.data() });
}
void qt_ui_log_error(const char* fmt, ...)
{
    auto ptr = dynamic_cast<SSRThread*>(QThread::currentThread());
    if (!ptr)
        return;
    QString str;
    va_list args1;
    va_start(args1, fmt);
    va_list args2;
    va_copy(args2, args1);
    std::vector<char> buf(1 + std::vsnprintf(nullptr, 0, fmt, args1));
    va_end(args1);
    std::vsnprintf(buf.data(), buf.size(), fmt, args2);
    va_end(args2);
    emit ptr->onSSRThreadLog(QString { buf.data() });
}

void send_traffic_stat(uint64_t tx, uint64_t rx)
{
    auto ptr = dynamic_cast<SSRThread*>(QThread::currentThread());
    if (!ptr)
        return;
    emit ptr->OnDataReady(tx, rx);
}
