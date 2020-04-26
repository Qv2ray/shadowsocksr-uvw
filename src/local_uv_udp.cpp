#include <memory>

#include "Buffer.hpp"
#include "UDPConnectionContext.hpp"
#include "ssrutils.h"
#include "uvw_single.hpp"
#include <cstdint>
#include <unordered_map>

#ifdef IP_TOS
#define SET_IP_TOS(h)                                                      \
    do {                                                                   \
        uv_os_fd_t fd = h->fileno();                                       \
        int tos = 46 << 2;                                                 \
        int rc = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));    \
        if (rc < 0 && errno != ENOPROTOOPT) {                              \
            LOGE("setting ipv4 dscp failed: %d", errno);                   \
        }                                                                  \
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)); \
        if (rc < 0 && errno != ENOPROTOOPT) {                              \
            LOGE("setting ipv6 dscp failed: %d", errno);                   \
        }                                                                  \
    } while (0)
#else
#define SET_IP_TOS(fd)
#endif //IP_TOS
namespace
{

inline uint16_t load16_be(const void* s)
{
    const auto* in = (const uint8_t*)s;
    return ((uint16_t)in[0] << 8)
        | ((uint16_t)in[1]);
}

}

class UDPRelay
{
private:
    struct SockaddrHasher
    {
        // https://www.boost.org/doc/libs/1_72_0/boost/container_hash/hash.hpp
        std::size_t operator()(const uvw::Addr& s) const
        {
            std::hash<std::string> strHasher;
            std::size_t h = strHasher(s.ip);
            h ^= std::hash<int> {}(s.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    struct SockAddrEqual
    {
        bool operator()(const uvw::Addr& t1,const uvw::Addr& t2) const
        {
            return t1.ip==t2.ip&&t1.port==t2.port;
        }

    };

    CipherEnv* cipherEnvPtr = nullptr;
    static constexpr int MAX_UDP_PACKET_SIZE = 65507;
    static constexpr int PACKET_HEADER_SIZE = 1 + 28 + 2 + 64;
    static constexpr int DEFAULT_PACKET_SIZE = 1492 - PACKET_HEADER_SIZE; //the default MTU for UDP relay
    std::unique_ptr<Buffer> localBuf;
    std::shared_ptr<uvw::Loop> loop;
    std::shared_ptr<uvw::UDPHandle> udpServer;
    std::unordered_map<uvw::Addr, std::shared_ptr<UDPConnectionContext>, SockaddrHasher,SockAddrEqual> socketCache;
    int packet_size;
    int buf_size;
    std::string serverHost;
    sockaddr remoteAddr {};

private:
    int parseUDPRelayHeader(const char* buf, const size_t buf_len,
        char* host, char* port, struct sockaddr_storage* storage)
    {
        const uint8_t atyp = *(uint8_t*)buf;
        int offset = 1;

        // get remote addr and port
        if ((atyp & ADDRTYPE_MASK) == 1) {
            // IP V4
            size_t in_addr_len = sizeof(struct in_addr);
            if (buf_len >= in_addr_len + 3) {
                if (storage != nullptr) {
                    auto* addr = (struct sockaddr_in*)storage;
                    addr->sin_family = AF_INET;
                    memcpy(&addr->sin_addr, buf + offset, sizeof(struct in_addr));
                    memcpy(&addr->sin_port, buf + offset + in_addr_len, sizeof(uint16_t));
                }
                if (host != nullptr) {
                    uv_inet_ntop(AF_INET, (const void*)(buf + offset),
                        host, INET_ADDRSTRLEN);
                }
                offset += in_addr_len;
            }
        } else if ((atyp & ADDRTYPE_MASK) == 3) {
            // Domain name
            uint8_t name_len = *(uint8_t*)(buf + offset);
            if (name_len + 4 <= buf_len) {
                if (storage != nullptr) {
                    char tmp[256] = { 0 };
                    memcpy(tmp, buf + offset + 1, name_len);
                    auto getAddrInfoReq = loop->resource<uvw::GetAddrInfoReq>();
                    //there use a dirty hack in uvw api. CHECK addrInfoSync to MODIFY.
                    //uvw addInfoSync don't support service or node be a nullptr
                    //which is not what we want.
                    auto dns_res = getAddrInfoReq->addrInfoSync(tmp, "");
                    if (dns_res.first) {
                        if (dns_res.second->ai_family == AF_INET) {
                            auto* addr = (struct sockaddr_in*)storage;
                            uv_inet_pton(AF_INET, tmp, &(addr->sin_addr));
                            memcpy(&addr->sin_port, buf + offset + 1 + name_len, sizeof(uint16_t));
                            addr->sin_family = AF_INET;
                        } else if (dns_res.second->ai_family == AF_INET6) {
                            auto* addr = (struct sockaddr_in6*)storage;
                            uv_inet_pton(AF_INET, tmp, &(addr->sin6_addr));
                            memcpy(&addr->sin6_port, buf + offset + 1 + name_len, sizeof(uint16_t));
                            addr->sin6_family = AF_INET6;
                        }
                    }
                    if (!dns_res.first) {
                        LOGE("[udp] parse udp header DNS not resolved");
                        return 0; // dns not resolved
                    }
                }
                if (host != nullptr) {
                    memcpy(host, buf + offset + 1, name_len);
                }
                offset += 1 + name_len;
            }
        } else if ((atyp & ADDRTYPE_MASK) == 4) {
            // IP V6
            size_t in6_addr_len = sizeof(struct in6_addr);
            if (buf_len >= in6_addr_len + 3) {
                if (storage != nullptr) {
                    auto* addr = (struct sockaddr_in6*)storage;
                    addr->sin6_family = AF_INET6;
                    memcpy(&addr->sin6_addr, buf + offset, sizeof(struct in6_addr));
                    memcpy(&addr->sin6_port, buf + offset + in6_addr_len, sizeof(uint16_t));
                }
                if (host != nullptr) {
                    uv_inet_ntop(AF_INET6, (const void*)(buf + offset),
                        host, INET6_ADDRSTRLEN);
                }
                offset += in6_addr_len;
            }
        }

        if (offset == 1) {
            LOGE("[udp] invalid header with addr type %d", atyp);
            return 0;
        }

        if (port != nullptr) {
            sprintf(port, "%d", load16_be(buf + offset));
        }
        offset += 2;

        return offset;
    }

    void remoteRecv(uvw::UDPDataEvent& data, uvw::UDPHandle& handle, const uvw::Addr& localSrcAddr)
    {
        if (socketCache.find(localSrcAddr)==socketCache.end())
            return;//panic
        auto& ctx = socketCache[localSrcAddr];
        ctx->remoteBuf->copy(data);
        int err = ctx->remoteBuf->ssDecryptALl(*cipherEnvPtr);
        if (err) {
            //panic
        }
        ctx->remoteBuf->protocolPluginUDPPostDecrypt(*ctx);
        if (static_cast<int>(ctx->remoteBuf->length())) {
            LOGE("client_udp_post_decrypt");
            //panic
            return;
        }
        int len = parseUDPRelayHeader(*ctx->remoteBuf->getBufPtr(), ctx->remoteBuf->length(), NULL, NULL, NULL);
        if (len == 0) {
            // error when parsing header
            LOGE("[udp] error in parse header");
            //panic
        }
        //ctx->remoteBuf->bufRealloc(ctx->remoteBuf->length()+3);

    }

    void serverRecv(uvw::UDPDataEvent& data, uvw::UDPHandle& handle)
    {
        /*
         *
         * SOCKS5 UDP Request
         * +----+------+------+----------+----------+----------+
         * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
         * +----+------+------+----------+----------+----------+
         * | 2  |  1   |  1   | Variable |    2     | Variable |
         * +----+------+------+----------+----------+----------+
         *
         * SOCKS5 UDP Response
         * +----+------+------+----------+----------+----------+
         * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
         * +----+------+------+----------+----------+----------+
         * | 2  |  1   |  1   | Variable |    2     | Variable |
         * +----+------+------+----------+----------+----------+
         *
         * shadowsocks UDP Request (before encrypted)
         * +------+----------+----------+----------+
         * | ATYP | DST.ADDR | DST.PORT |   DATA   |
         * +------+----------+----------+----------+
         * |  1   | Variable |    2     | Variable |
         * +------+----------+----------+----------+
         *
         * shadowsocks UDP Response (before encrypted)
         * +------+----------+----------+----------+
         * | ATYP | DST.ADDR | DST.PORT |   DATA   |
         * +------+----------+----------+----------+
         * |  1   | Variable |    2     | Variable |
         * +------+----------+----------+----------+
         *
         * shadowsocks UDP Request and Response (after encrypted)
         * +-------+--------------+
         * |   IV  |    PAYLOAD   |
         * +-------+--------------+
         * | Fixed |   Variable   |
         * +-------+--------------+
         *
         */
        if (data.length > packet_size) {
            LOGE("[udp] remote_recv_recvfrom fragmentation");
            //panic
        }
        char addr_header[512] = { 0 };
        int addr_header_len = 0;
        int frag = data.data[2];
        char host[257] = { 0 };
        char port[65] = { 0 };
        unsigned int offset = 3;
        sockaddr_storage dst_addr;
        memset(&dst_addr, 0, sizeof(struct sockaddr_storage));
        addr_header_len = parseUDPRelayHeader(data.data.get() + offset,
            data.length - offset, host, port, &dst_addr);
        if (addr_header_len == 0) {
            //panic
        }
        strncpy(addr_header, data.data.get()+ offset, addr_header_len);
        if(socketCache.find(data.sender)!=socketCache.end()) {
            auto& ctx=socketCache[data.sender];
            if (!SockAddrEqual{}(data.sender,ctx->srcAddr)) {
                socketCache.erase(data.sender);
            }
        }
        if (frag) {
            LOGE("[udp] drop a message since frag is not 0, but %d", frag);
            //panic
        }
        std::shared_ptr<UDPConnectionContext> remoteCtx;
        if(socketCache.find(data.sender)==socketCache.end()) {
            //check again
            auto remoteSocket=loop->resource<uvw::UDPHandle>();
            SET_IP_TOS(remoteSocket);
            //addrheader;
            remoteSocket->bind(remoteAddr);
            remoteCtx=std::make_shared<UDPConnectionContext>(data.sender,remoteSocket);
            socketCache.insert({data.sender,remoteCtx});
            remoteSocket->on<uvw::UDPDataEvent>([this,addr=data.sender](auto&e,auto&h){
                        this->remoteRecv(e,h,addr);
                        });
            remoteSocket->recv();
        } else {
            remoteCtx = socketCache[data.sender];
        }
        if (offset > 0) {
            localBuf->copyFromBegin(data.data.get()+offset,data.length-offset);
        }
        localBuf->protocolPluginUDPPreEncrypt(*remoteCtx);
        int err = localBuf->ssEncryptAll(*cipherEnvPtr);
        if(err){
            //panic
        }
        if(localBuf->length()>packet_size){
            LOGE("[udp] server_recv_sendto fragmentation");
            //panic
        }
        remoteCtx->remote->send(remoteAddr,localBuf->duplicateDataToArray(),localBuf->length());
    }

public:
    int initUDPRelay(int mtu, const char* host, int port)
    {
        if (mtu > 0) {
            packet_size = mtu - PACKET_HEADER_SIZE;
            buf_size = packet_size * 2;
        }
        udpServer = loop->resource<uvw::UDPHandle>();
        SET_IP_TOS(udpServer);
        udpServer->bind(host, port, uvw::Flags<uvw::UDPHandle::Bind>::from<uvw::UDPHandle::Bind::REUSEADDR>());
        udpServer->on<uvw::UDPDataEvent>([this](auto& e, auto& h) {
            localBuf = std::make_unique<Buffer>();
            serverRecv(e, h);
        });
        udpServer->recv();
        return 0;
    }
};
