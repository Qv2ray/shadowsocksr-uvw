#pragma once
#include <cstdint>

struct ssr_ipv4
{
    union {
        uint8_t u8[4];
        uint16_t u16[2];
        uint32_t u32;
    } _;
};

struct ssr_ipv6
{
    union {
        uint8_t u8[16];
        uint16_t u16[8];
        uint32_t u32[4];
        uint64_t u64[2];
    } _;
};

struct ssr_ip
{
    unsigned int version;
    union {
        struct ssr_ipv4 v4;
        struct ssr_ipv6 v6;
    } ip;
};
