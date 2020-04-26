#if !defined(__sockaddr_universal_h__)
#define __sockaddr_universal_h__ 1

#ifdef __cplusplus
extern "C"
{
#endif
#if defined(_WIN32)
#include <WS2tcpip.h>
#else
#include <netinet/in.h>
#endif // defined(_WIN32)

#include <stdbool.h>
#include <stdint.h>

    enum SOCKS5_ADDRTYPE {
        SOCKS5_ADDRTYPE_INVALID = 0x00,
        SOCKS5_ADDRTYPE_IPV4 = 0x01,
        SOCKS5_ADDRTYPE_DOMAINNAME = 0x03,
        SOCKS5_ADDRTYPE_IPV6 = 0x04,
    };

    struct socks5_address
    {
        enum SOCKS5_ADDRTYPE addr_type;
        union {
            struct in_addr ipv4;
            struct in6_addr ipv6;
            char domainname[0x0100];
        } addr;
        uint16_t port;
    };

    bool socks5_address_parse(const uint8_t* data, size_t len, struct socks5_address* addr);

#ifdef __cplusplus
}
#endif
#endif // !defined(__sockaddr_universal_h__)
