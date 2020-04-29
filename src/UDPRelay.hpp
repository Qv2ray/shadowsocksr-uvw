#ifndef SHADOWSOCKSR_UVW_UDPRELAY_HPP
#define SHADOWSOCKSR_UVW_UDPRELAY_HPP

#include <memory>

#include "uvw_single.hpp"
#include <cstdint>
#include <unordered_map>

extern "C"
{
#include "encrypt.h"
#include "obfs/obfs.h"
#include "shadowsocksr.h"
}
class CipherEnv;
class ObfsClass;
class Buffer;
class UDPConnectionContext;

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
        bool operator()(const uvw::Addr& t1, const uvw::Addr& t2) const
        {
            return t1.ip == t2.ip && t1.port == t2.port;
        }
    };

    int parseUDPRelayHeader(const char* buf, size_t buf_len,
        char* host, char* port, struct sockaddr_storage* storage);

    void remoteRecv(uvw::UDPDataEvent& data, uvw::UDPHandle& handle, const uvw::Addr& localSrcAddr);

    void panic(const uvw::Addr& addr);

    void serverRecv(uvw::UDPDataEvent& data, uvw::UDPHandle& handle);

public:
    UDPRelay(std::shared_ptr<uvw::Loop> loop, CipherEnv& cipherEnv, ObfsClass& obfsClass, const profile_t& profile);

    ~UDPRelay();

    int initUDPRelay(int mtu, const char* host, int port, sockaddr remote_addr);

private:
    CipherEnv* cipherEnvPtr;

public:
    std::unique_ptr<obfs_class, decltype(free)*> protocol_plugin;
    std::unique_ptr<obfs, decltype(obfs_class::dispose)> protocolPtr;

private:
    void* protocol_global = nullptr;
    int timeout;
    static constexpr int MAX_UDP_PACKET_SIZE = 65507;
    static constexpr int PACKET_HEADER_SIZE = 1 + 28 + 2 + 64;
    static constexpr int DEFAULT_PACKET_SIZE = 1492 - PACKET_HEADER_SIZE; //the default MTU for UDP relay
    std::unique_ptr<Buffer> localBuf;
    std::shared_ptr<uvw::Loop> loop;
    std::shared_ptr<uvw::UDPHandle> udpServer;
    std::unordered_map<uvw::Addr, std::shared_ptr<UDPConnectionContext>, SockaddrHasher, SockAddrEqual> socketCache;
    int packet_size { DEFAULT_PACKET_SIZE };
    int buf_size { DEFAULT_PACKET_SIZE * 2 };
    sockaddr remoteAddr {};
};

#endif //SHADOWSOCKSR_UVW_UDPRELAY_HPP
