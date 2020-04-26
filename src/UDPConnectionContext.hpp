#ifndef SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
#define SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
#include <memory>
extern "C"
{
#include "obfs/obfs.h"
#include "shadowsocks.h"
}
#include "Buffer.hpp"
#include "CipherEnv.hpp"
#include "ObfsClass.hpp"
#include "uvw_single.hpp"

class UDPConnectionContext
{
public:
    std::unique_ptr<obfs_class, decltype(free)*> protocol_plugin;
    std::unique_ptr<obfs, decltype(obfs_class::dispose)> protocolPtr;

private:
    void* protocol_global = nullptr;

public:
    uvw::Addr srcAddr;
    std::unique_ptr<Buffer> remoteBuf;
    std::shared_ptr<uvw::UDPHandle> remote;
    UDPConnectionContext();
    UDPConnectionContext(uvw::Addr addr,std::shared_ptr<uvw::UDPHandle> remoteSocket);
    void setSrcAddr(uvw::Addr addr);
    server_info_t construct_obfs(CipherEnv& cipherEnv, ObfsClass& obfsClass, const profile_t& profile);
    ~UDPConnectionContext();
};

#endif //SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
