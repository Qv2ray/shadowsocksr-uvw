#include "SSRThread.hpp"
#include "TCPRelay.hpp"
SSRThread::SSRThread(int localPort,
    int remotePort,
    std::string local_addr,
    std::string remote_host,
    std::string method,
    std::string password,
    std::string obfs,
    std::string obfs_param,
    std::string protocol,
    std::string protocol_param)
    : localPort(localPort)
    , remotePort(remotePort)
    , local_addr(std::move(local_addr))
    , remote_host(std::move(remote_host))
    , method(std::move(method))
    , password(std::move(password))
    , obfs(std::move(obfs))
    , obfs_param(std::move(obfs_param))
    , protocol(std::move(protocol))
    , protocol_param(std::move(protocol_param))
    , tcpRelay(TCPRelay::create())
{
}

SSRThread::SSRThread(int localPort,
    int remotePort,
    int timeout,
    int mtu,
    SSR_WORK_MODE work_mode,
    std::string local_addr,
    std::string remote_host,
    std::string method,
    std::string password,
    std::string obfs,
    std::string obfs_param,
    std::string protocol,
    std::string protocol_param,
    int ipv6first,
    int verbose)
    : localPort(localPort)
    , remotePort(remotePort)
    , timeout(timeout)
    , mtu(mtu)
    , mode(static_cast<int>(work_mode))
    , local_addr(std::move(local_addr))
    , remote_host(std::move(remote_host))
    , method(std::move(method))
    , password(std::move(password))
    , obfs(std::move(obfs))
    , obfs_param(std::move(obfs_param))
    , protocol(std::move(protocol))
    , protocol_param(std::move(protocol_param))
    , ipv6first(ipv6first)
    , verbose(verbose)
    , tcpRelay(TCPRelay::create())
{
}

SSRThread::~SSRThread()
{
    tcpRelay->stop();
}

void SSRThread::run()
{
    profile_t profile;
    profile.remote_host = remote_host.data();
    profile.local_addr = local_addr.empty() ? nullptr : local_addr.data();
    profile.method = method.data();
    profile.timeout = timeout;
    profile.password = password.data();
    profile.obfs = obfs.data();
    profile.obfs_param = obfs_param.data();
    profile.protocol = protocol.data();
    profile.protocol_param = protocol_param.data();
    profile.remote_port = remotePort;
    profile.local_port = localPort;
    profile.mtu = mtu;
    profile.mode = mode;
    profile.acl = nullptr;
    profile.fast_open = 1; // libuv is not supported fastopen yet.
    profile.verbose = verbose;
    profile.ipv6first = ipv6first;
    tcpRelay->loopMain(profile);
}

void SSRThread::stop()
{
    if (isRunning()) {
        tcpRelay->stop();
        wait();
    }
}
