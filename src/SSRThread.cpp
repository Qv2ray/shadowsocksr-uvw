#include "SSRThread.hpp"
#include "shadowsocks.h"
SSRThread::SSRThread(int localPort,
                     int remotePort,
                     std::string local_addr,
                     std::string remote_host,
                     std::string method,
                     std::string password,
                     std::string obfs,
                     std::string obfs_param,
                     std::string protocol,
                     std::string protocol_param,
                     QString inboundTag):
      localPort(localPort),
      remotePort(remotePort),
      local_addr(std::move(local_addr)),
      remote_host(std::move(remote_host)),
      method(std::move(method)),
      password(std::move(password)),
      obfs(std::move(obfs)),
      obfs_param(std::move(obfs_param)),
      protocol(std::move(protocol)),
      protocol_param(std::move(protocol_param)),
      inboundTag(std::move(inboundTag))
{

}
QString SSRThread::getInboundTag()
{
    return inboundTag;
}
void SSRThread::run()
{
    profile_t profile;
    profile.remote_host = remote_host.data();
    profile.local_addr = local_addr.empty() ? nullptr : local_addr.data();
    profile.method = method.data();
    profile.timeout = 600;
    profile.password = password.data();
    profile.obfs = obfs.data();
    profile.obfs_param = obfs_param.data();
    profile.protocol = protocol.data();
    profile.protocol_param = protocol_param.data();
    profile.remote_port = remotePort;
    profile.local_port = localPort;
    profile.mtu = 0;//we don't use udp relay, therefore we set mtu to zero.
    profile.mode = 0;//we don't use udp relay, therefore we set mode to zero.
    profile.acl = nullptr;
    profile.fast_open = 1;
    profile.mptcp = 0;
    start_ssr_uv_local_server(profile);
}

SSRThread::~SSRThread()
{
    if(isRunning())
    {
        stop_ss_local_server();
        wait();
    }
}
