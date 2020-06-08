#ifndef QT_UI_LOG_H
#define QT_UI_LOG_H
#ifdef __cplusplus
extern "C"
{
#include <cstdint>
#else
#include <stdint.h>
#endif
    void qt_ui_log(const char* msg);
    void send_traffic_stat(uint64_t, uint64_t);
#ifdef __cplusplus
}
#endif
#endif // QT_UI_LOG_H
