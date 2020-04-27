#include "UDPConnectionContext.hpp"

#include "Buffer.hpp"

UDPConnectionContext::~UDPConnectionContext()
{
    if (remote) {
        remote->clear();
        remote->close();
    }
}

UDPConnectionContext::UDPConnectionContext(uvw::Addr addr, std::shared_ptr<uvw::UDPHandle> remoteSocket)
    : srcAddr(std::move(addr))
    , remoteBuf(std::make_unique<Buffer>())
    , remote(std::move(remoteSocket))
{
}
void UDPConnectionContext::initTimer(std::shared_ptr<uvw::Loop>& loop, std::function<void()> panic, uvw::TimerHandle::Time timeout)
{
    timeoutTimer = loop->resource<uvw::TimerHandle>();
    timeoutTimer->on<uvw::TimerEvent>([addr = srcAddr, panic = std::move(panic)](auto&, uvw::TimerHandle& h) {
        h.stop();
        h.close();
        //before we panic, we must stop and close silently.
        panic();//destroy this UDPConnectionContext instance.
    });
    timeoutTimer->start(timeout, timeout);
}
void UDPConnectionContext::resetTimeoutTimer()
{
    if (timeoutTimer)
        timeoutTimer->again();
}
