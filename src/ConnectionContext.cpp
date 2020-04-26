#include "ConnectionContext.hpp"

#include "Buffer.hpp"
#include "LogHelper.h"
#include "ObfsClass.hpp"
#include "uvw_single.hpp"
namespace
{
void dummyDisposeObfs(obfs*)
{
}
void dummyDisposeEncCtx(struct enc_ctx*)
{
}

} // namespace

ConnectionContext::ConnectionContext(std::shared_ptr<uvw::TCPHandle> tcpHandle, ObfsClass* obfsClassPtr, CipherEnv* cipherEnvPtr)
    : obfsClassPtr(obfsClassPtr)
    , cipherEnvPtr(cipherEnvPtr)
    , localBuf { new Buffer }
    , protocolPtr { nullptr, obfsClassPtr->protocol_plugin == nullptr ? dummyDisposeObfs : obfsClassPtr->protocol_plugin->dispose }
    , obfsPtr { nullptr, obfsClassPtr->obfs_plugin == nullptr ? dummyDisposeObfs : obfsClassPtr->obfs_plugin->dispose }
    , e_ctx { nullptr, dummyDisposeEncCtx }
    , d_ctx { nullptr, dummyDisposeEncCtx }
    , client(std::move(tcpHandle))
{
}

ConnectionContext::ConnectionContext()
    : localBuf {}
    , protocolPtr { nullptr, dummyDisposeObfs }
    , obfsPtr { nullptr, dummyDisposeObfs }
    , e_ctx { nullptr, dummyDisposeEncCtx }
    , d_ctx {
        nullptr, dummyDisposeEncCtx
    }
{
}

ConnectionContext::ConnectionContext(ConnectionContext&& that) noexcept
    : obfsClassPtr(that.obfsClassPtr)
    , cipherEnvPtr(that.cipherEnvPtr)
    , localBuf { std::move(that.localBuf) }
    , remoteBuf { std::move(that.remoteBuf) }
    , protocolPtr { std::move(that.protocolPtr) }
    , obfsPtr { std::move(that.obfsPtr) }
    , e_ctx { std::move(that.e_ctx) }
    , d_ctx { std::move(
          that.d_ctx) }
    , client(std::move(that.client))
    , remote(std::move(that.remote))
{
}

ConnectionContext& ConnectionContext::operator=(ConnectionContext&& that) noexcept
{

    localBuf = std::move(that.localBuf);
    remoteBuf = std::move(that.remoteBuf);
    protocolPtr = std::move(that.protocolPtr);
    obfsPtr = std::move(that.obfsPtr);
    e_ctx = std::move(that.e_ctx);
    d_ctx = std::move(that.d_ctx);
    client = std::move(that.client);
    remote = std::move(that.remote);
    obfsClassPtr = that.obfsClassPtr;
    cipherEnvPtr = that.cipherEnvPtr;
    return *this;
}

void ConnectionContext::setRemoteTcpHandle(std::shared_ptr<uvw::TCPHandle> tcp)
{
    remote = std::move(tcp);
}

server_info_t ConnectionContext::construct_obfs(CipherEnv& cipherEnv, ObfsClass& obfsClass, const profile_t& profile, int server_info_head_len)
{
    server_info_t _server_info;
    memset(&_server_info, 0, sizeof(server_info_t));
    if (cipherEnv.cipher.enc_method > TABLE) {
        auto encCtxRelease = [this](struct enc_ctx* p) {
            if (p == nullptr)
                return;
            enc_ctx_release(&this->cipherEnvPtr->cipher, p);
        };
        e_ctx = { reinterpret_cast<struct enc_ctx*>(malloc(sizeof(struct enc_ctx))), encCtxRelease };
        d_ctx = { reinterpret_cast<struct enc_ctx*>(malloc(sizeof(struct enc_ctx))), encCtxRelease };
        enc_ctx_init(&cipherEnv.cipher, e_ctx.get(), 1);
        enc_ctx_init(&cipherEnv.cipher, d_ctx.get(), 0);
    }
    if (profile.remote_host)
        strcpy(_server_info.host, profile.remote_host);
    _server_info.port = profile.remote_port;
    _server_info.param = profile.obfs_param;
    _server_info.g_data = obfsClass.obfs_global;
    _server_info.head_len = server_info_head_len;
    _server_info.iv_len = enc_get_iv_len(&cipherEnv.cipher);
    _server_info.iv = e_ctx->evp.iv;
    _server_info.key = enc_get_key(&cipherEnv.cipher);
    _server_info.key_len = enc_get_key_len(&cipherEnv.cipher);
    _server_info.tcp_mss = 1452;
    _server_info.buffer_size = 2048;
    _server_info.cipher_env = &cipherEnv.cipher;

    if (obfsClass.obfs_plugin) {
        this->obfsPtr.reset(obfsClass.obfs_plugin->new_obfs());
        obfsClass.obfs_plugin->set_server_info(obfsPtr.get(), &_server_info);
    }

    _server_info.param = profile.protocol_param;
    _server_info.g_data = obfsClass.protocol_global;

    if (obfsClass.protocol_plugin) {
        protocolPtr.reset(obfsClass.protocol_plugin->new_obfs());
        _server_info.overhead = obfsClass.protocol_plugin->get_overhead(protocolPtr.get()) + (obfsClass.obfs_plugin ? obfsClass.obfs_plugin->get_overhead(obfsPtr.get()) : 0);
        obfsClass.protocol_plugin->set_server_info(protocolPtr.get(), &_server_info);
    }
    return _server_info;
}

ConnectionContext::~ConnectionContext()
{
    if (remote) {
        remote->close();
    }
    if (client) {
        client->close();
    }
}
