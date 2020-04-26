
#include <memory.h>
#include <uv.h>

#if !defined(_WIN32)
#include <netdb.h>
#endif // !defined(_WIN32)

#include "sockaddr_universal.h"

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
// data start from atyp
bool socks5_address_parse(const uint8_t* data, size_t len, struct socks5_address* addr)
{
    size_t offset = 0;
    size_t addr_size = 0;
    uint8_t addr_type = 0;

    if (data == NULL || len == 0 || addr == NULL) {
        return false;
    }

    addr_type = data[offset++];

    switch ((enum SOCKS5_ADDRTYPE)addr_type) {
    case SOCKS5_ADDRTYPE_IPV4:
        addr_size = sizeof(struct in_addr);
        if (len < sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
            return false;
        }
        addr->addr_type = SOCKS5_ADDRTYPE_IPV4;
        memcpy(&addr->addr.ipv4, data + offset, addr_size);
        break;
    case SOCKS5_ADDRTYPE_DOMAINNAME:
        addr_size = (size_t)data[offset++];
        if (len < sizeof(uint8_t) + sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
            return false;
        }
        addr->addr_type = SOCKS5_ADDRTYPE_DOMAINNAME;
        memset(addr->addr.domainname, 0, sizeof(addr->addr.domainname));
        memcpy(addr->addr.domainname, data + offset, addr_size);
        break;
    case SOCKS5_ADDRTYPE_IPV6:
        addr_size = sizeof(struct in6_addr);
        if (len < sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
            return false;
        }
        addr->addr_type = SOCKS5_ADDRTYPE_IPV6;
        memcpy(&addr->addr.ipv6, data + offset, addr_size);
        break;
    default:
        addr->addr_type = SOCKS5_ADDRTYPE_INVALID;
        return false;
        break;
    }
    offset += addr_size;

    addr->port = ntohs(*((uint16_t*)(data + offset)));

    offset += sizeof(uint16_t);

    return true;
}
