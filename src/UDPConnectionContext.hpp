#ifndef SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
#define SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
#include <memory>

#include "uvw_single.hpp"
class Buffer;

class UDPConnectionContext
{
public:
    std::shared_ptr<uvw::TimerHandle> timeoutTimer;
    uvw::Addr srcAddr;
    std::unique_ptr<Buffer> remoteBuf;
    std::shared_ptr<uvw::UDPHandle> remote;
    UDPConnectionContext() = default;
    UDPConnectionContext(uvw::Addr addr, std::shared_ptr<uvw::UDPHandle> remoteSocket);
    void initTimer(std::shared_ptr<uvw::Loop>& loop, std::function<void()> panic, uvw::TimerHandle::Time timeout);
    void resetTimeoutTimer();
    ~UDPConnectionContext();
};

#endif //SHADOWSOCKSR_UVW_UDPCONNECTIONCONTEXT_HPP
