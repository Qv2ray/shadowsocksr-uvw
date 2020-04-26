#ifndef OBFSCLASS_H
#define OBFSCLASS_H
#include "obfs/obfs.h"

#include <memory>
class ObfsClass
{
public:
    std::unique_ptr<obfs_class, decltype(free)*> protocol_plugin;
    std::unique_ptr<obfs_class, decltype(free)*> obfs_plugin;
    void* obfs_global = nullptr;
    void* protocol_global = nullptr;
    ObfsClass(const char* protocol, const char* obfs_name);
    ~ObfsClass();
};
#endif // OBFSCLASS_H
