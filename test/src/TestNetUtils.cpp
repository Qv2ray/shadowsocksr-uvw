#include "NetUtils.hpp"
#include "uvw/loop.h"
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include <cstring>

TEST_CASE("GetSockAddr for IPv4", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto ip = "220.181.38.148";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, ip, port, &storage, true);
    REQUIRE(res == 0);
    uv_ip4_addr(ip, port, reinterpret_cast<struct sockaddr_in*>(&storage2));
    for (auto i = 0; i < sizeof(sockaddr_storage); ++i) {
        auto storage_ptr = reinterpret_cast<char*>(&storage);
        auto storage2_ptr = reinterpret_cast<char*>(&storage2);
        REQUIRE(storage_ptr[i] == storage2_ptr[i]);
    }
}

TEST_CASE("GetSockAddr for IPv4 invalid", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto ip = "299.299.299.299";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, ip, port, &storage, true);
    REQUIRE(res != 0);
}

TEST_CASE("GetSockAddr for IPv6 invalid", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto ip = "fe80::1::2";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, ip, port, &storage, true);
    REQUIRE(res != 0);
}

TEST_CASE("GetSockAddr for IPv6", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto ip = "2607:f8b0:4007:804::200e";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, ip, port, &storage, true);
    REQUIRE(res == 0);
    uv_ip6_addr(ip, port, reinterpret_cast<struct sockaddr_in6*>(&storage2));
    for (auto i = 0; i < sizeof(sockaddr_storage); ++i) {
        auto storage_ptr = reinterpret_cast<char*>(&storage);
        auto storage2_ptr = reinterpret_cast<char*>(&storage2);
        REQUIRE(storage_ptr[i] == storage2_ptr[i]);
    }
}

TEST_CASE("GetSockAddr for host ipv4", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto host = "google.com";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, host, port, &storage, false);
    REQUIRE(res == 0);
    uv_getaddrinfo_t req;
    struct addrinfo hints;
    char digitBuffer[20] = { 0 };
    sprintf(digitBuffer, "%d", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    res = uv_getaddrinfo(loop->raw(), &req, nullptr, host, digitBuffer, &hints);
    REQUIRE(res == 0);
    struct addrinfo* rp = nullptr;
    std::unique_ptr<struct addrinfo, decltype(uv_freeaddrinfo)*> guard { req.addrinfo, &uv_freeaddrinfo };
    for (rp = req.addrinfo; rp != nullptr; rp = rp->ai_next)
        if (rp->ai_family == AF_INET) {
            if (rp->ai_family == AF_INET)
                memcpy(&storage2, rp->ai_addr, sizeof(struct sockaddr_in));
            else if (rp->ai_family == AF_INET6)
                memcpy(&storage2, rp->ai_addr, sizeof(struct sockaddr_in6));
            break;
        }
    for (auto i = 0; i < sizeof(sockaddr_storage); ++i) {
        auto storage_ptr = reinterpret_cast<char*>(&storage);
        auto storage2_ptr = reinterpret_cast<char*>(&storage2);
        REQUIRE(storage_ptr[i] == storage2_ptr[i]);
    }
}

TEST_CASE("GetSockAddr for host ipv6", "[netutils]")
{
    auto loop = uvw::Loop::create();
    sockaddr_storage storage {};
    sockaddr_storage storage2 {};
    auto host = "ipv6.google.com";
    auto port = 443;
    int res = ssr_get_sock_addr(loop, host, port, &storage, true);
    REQUIRE(res == 0);
    uv_getaddrinfo_t req;
    struct addrinfo hints;
    char digitBuffer[20] = { 0 };
    sprintf(digitBuffer, "%d", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    res = uv_getaddrinfo(loop->raw(), &req, nullptr, host, digitBuffer, &hints);
    REQUIRE(res == 0);
    struct addrinfo* rp = nullptr;
    std::unique_ptr<struct addrinfo, decltype(uv_freeaddrinfo)*> guard { req.addrinfo, &uv_freeaddrinfo };
    for (rp = req.addrinfo; rp != nullptr; rp = rp->ai_next)
        if (rp->ai_family == AF_INET6) {
            if (rp->ai_family == AF_INET)
                memcpy(&storage2, rp->ai_addr, sizeof(struct sockaddr_in));
            else if (rp->ai_family == AF_INET6)
                memcpy(&storage2, rp->ai_addr, sizeof(struct sockaddr_in6));
            break;
        }
    for (auto i = 0; i < sizeof(sockaddr_storage); ++i) {
        auto storage_ptr = reinterpret_cast<char*>(&storage);
        auto storage2_ptr = reinterpret_cast<char*>(&storage2);
        REQUIRE(storage_ptr[i] == storage2_ptr[i]);
    }
}
