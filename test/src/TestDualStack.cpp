#include "uvw/tcp.h"
#include <iostream>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Dual-Stack", "[tcp]")
{
    auto loop = uvw::Loop::create();

    auto tcpServer = loop->resource<uvw::TCPHandle>();
    struct sockaddr_in6 sin6;
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(10000);
    auto client1 = loop->resource<uvw::TCPHandle>();
    auto client2 = loop->resource<uvw::TCPHandle>();
    int client_count = 0;
    tcpServer->on<uvw::ListenEvent>([&client_count](const uvw::ListenEvent&, uvw::TCPHandle& handle) {
        std::shared_ptr<uvw::TCPHandle> socket = handle.loop().resource<uvw::TCPHandle>();

        socket->on<uvw::ErrorEvent>([](const uvw::ErrorEvent&, uvw::TCPHandle&) { FAIL(); });
        socket->on<uvw::CloseEvent>([&handle](const uvw::CloseEvent&, uvw::TCPHandle&) { handle.close(); });
        socket->on<uvw::EndEvent>([](const uvw::EndEvent&, uvw::TCPHandle& sock) { sock.close(); });

        handle.accept(*socket);
        socket->read();
        client_count += 1;
        std::cout << "peer:" << socket->peer<uvw::IPv6>().ip << std::endl;
    });

    client1->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& handle) {
        handle.close();
    });
    client2->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& handle) {
        handle.close();
    });
    tcpServer->bind(reinterpret_cast<sockaddr&>(sin6));
    tcpServer->listen();
    client1->connect("127.0.0.1", 10000);
    client2->connect<uvw::IPv6>("::1", 10000);
    loop->run();
    REQUIRE(client_count == 2);
}

TEST_CASE("Single-Stack", "[tcp]")
{
    auto loop = uvw::Loop::create();
    auto tcpServer = loop->resource<uvw::TCPHandle>();
    struct sockaddr_in6 sin6;
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_loopback;
    sin6.sin6_port = htons(10000);
    auto client1 = loop->resource<uvw::TCPHandle>();
    auto client2 = loop->resource<uvw::TCPHandle>();
    int client_count = 0;
    tcpServer->on<uvw::ListenEvent>([&client_count](const uvw::ListenEvent&, uvw::TCPHandle& handle) {
        std::shared_ptr<uvw::TCPHandle> socket = handle.loop().resource<uvw::TCPHandle>();

        socket->on<uvw::ErrorEvent>([](const uvw::ErrorEvent&, uvw::TCPHandle&) { FAIL(); });
        socket->on<uvw::CloseEvent>([&handle](const uvw::CloseEvent&, uvw::TCPHandle&) { handle.close(); });
        socket->on<uvw::EndEvent>([](const uvw::EndEvent&, uvw::TCPHandle& sock) { sock.close(); });

        handle.accept(*socket);
        socket->read();
        client_count += 1;
        std::cout << "peer:" << socket->peer<uvw::IPv6>().ip << std::endl;
    });

    client1->once<uvw::ErrorEvent>([](auto&, uvw::TCPHandle& handle) {
        handle.close();
    });
    client1->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& handle) {
        handle.close();
    });
    client2->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& handle) {
        handle.close();
    });
    tcpServer->bind(reinterpret_cast<sockaddr&>(sin6));
    tcpServer->listen();
    client1->connect("127.0.0.1", 10000);
    client2->connect<uvw::IPv6>("::1", 10000);
    loop->run();
    REQUIRE(client_count == 1);
}
