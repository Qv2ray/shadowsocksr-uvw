#ifndef CONNECTIONCONTEXT_H
#define CONNECTIONCONTEXT_H
#include <memory>
extern "C"
{
#include "obfs/obfs.h"
#include "shadowsocksr.h"
}
#include "CipherEnv.hpp"
namespace uvw
{
class TCPHandle;
}
#include "Buffer.hpp"

#include <functional>
class ConnectionContext
{
private:
    ObfsClass* obfsClassPtr = nullptr;
    CipherEnv* cipherEnvPtr = nullptr;

public:
    using enc_ctx_release_t = std::function<void(struct enc_ctx*)>;
    std::unique_ptr<Buffer> localBuf;
    std::unique_ptr<Buffer> remoteBuf;
    std::unique_ptr<obfs, decltype(obfs_class::dispose)> protocolPtr;
    std::unique_ptr<obfs, decltype(obfs_class::dispose)> obfsPtr;
    std::unique_ptr<struct enc_ctx, enc_ctx_release_t> e_ctx;
    std::unique_ptr<struct enc_ctx, enc_ctx_release_t> d_ctx;
    std::shared_ptr<uvw::TCPHandle> client;
    std::shared_ptr<uvw::TCPHandle> remote;

    ConnectionContext(std::shared_ptr<uvw::TCPHandle> tcpHandle, ObfsClass* obfsClassPtr, CipherEnv* cipherEnvPtr);

    ConnectionContext();

    ConnectionContext(ConnectionContext&&) noexcept;

    ConnectionContext& operator=(ConnectionContext&&) noexcept;

    void setRemoteTcpHandle(std::shared_ptr<uvw::TCPHandle> tcp);

    server_info_t construct_obfs(CipherEnv& cipherEnv, ObfsClass& obfsClass, const profile_t& profile, int server_info_head_len);

    ~ConnectionContext();
};

#endif // CONNECTIONCONTEXT_H
