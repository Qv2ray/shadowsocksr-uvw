#ifndef LOGHELPER_H
#define LOGHELPER_H
#include "ssrutils.h"
struct LogHelper
{
    const char* p_;
    LogHelper(const char* p)
        : p_(p)
    {
        LOGI("enter %s", p);
    }
    ~LogHelper()
    {
        LOGI("leave %s", p_);
    }
};

#endif // LOGHELPER_H
