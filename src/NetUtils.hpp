#pragma once
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include <memory>

namespace uvw
{
class Loop;
}

int ssr_get_sock_addr(std::shared_ptr<uvw::Loop> loop, const char* host, int port, struct sockaddr_storage* storage, int ipv6first);
