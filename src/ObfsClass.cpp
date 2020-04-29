#include "ObfsClass.hpp"

ObfsClass::ObfsClass(const char* protocol, const char* obfs_name)
    : protocol_plugin(new_obfs_class(protocol), free)
    , obfs_plugin(new_obfs_class(obfs_name), free)
{
    if (protocol_plugin)
        protocol_global = protocol_plugin->init_data();
    if (obfs_plugin)
        obfs_global = obfs_plugin->init_data();
}

ObfsClass::~ObfsClass()
{
    if (protocol_global != nullptr) {
        free(protocol_global);
        protocol_global = nullptr;
    }
    if (obfs_global != nullptr) {
        free(obfs_global);
        obfs_global = nullptr;
    }
}
