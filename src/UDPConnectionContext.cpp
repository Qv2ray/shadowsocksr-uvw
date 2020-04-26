#include "UDPConnectionContext.hpp"

#include <utility>
namespace
{
void dummyDisposeObfs(obfs*)
{
}
} // namespace

server_info_t UDPConnectionContext::construct_obfs(CipherEnv& cipherEnv, ObfsClass& obfsClass, const profile_t& profile)
{
    protocol_plugin = { reinterpret_cast<obfs_class*>(new_obfs_class(profile.protocol)), free };
    if (protocol_plugin) {
        protocolPtr = { protocol_plugin->new_obfs(), protocol_plugin->dispose };
        protocol_global = protocol_plugin->init_data();
    }
    server_info_t serverInfo;
    memset(&serverInfo, 0, sizeof(server_info_t));
    strcpy(serverInfo.host, profile.local_addr);
    serverInfo.port = profile.local_port;
    serverInfo.g_data = protocol_global;
    serverInfo.param = profile.protocol_param;
    serverInfo.key = enc_get_key(&cipherEnv.cipher);
    serverInfo.key_len = enc_get_key_len(&cipherEnv.cipher);
    if (protocol_plugin)
        protocol_plugin->set_server_info(protocolPtr.get(), &serverInfo);
    return serverInfo;
}

UDPConnectionContext::~UDPConnectionContext()
{
    if (protocol_global) {
        free(protocol_global);
        protocol_global = nullptr;
    }
}

UDPConnectionContext::UDPConnectionContext()
    : protocol_plugin(nullptr, free)
    , protocolPtr(nullptr, dummyDisposeObfs)
{
}
void UDPConnectionContext::setSrcAddr(uvw::Addr addr)
{
    srcAddr=std::move(addr);
}
UDPConnectionContext::UDPConnectionContext(uvw::Addr addr, std::shared_ptr<uvw::UDPHandle> remoteSocket)
    : protocol_plugin(nullptr, free)
    , protocolPtr(nullptr, dummyDisposeObfs)
    , srcAddr(std::move(addr))
    , remoteBuf(std::make_unique<Buffer>())
    , remote(std::move(remoteSocket))
{
}
