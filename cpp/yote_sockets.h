#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

namespace yote {

enum class AddrInfoFlags : u{
    PASSIVE = 1 << 0,
};

enum class AddrInfoFamily : u8 {
    INET4 = AF_INET,
    INET6 = AF_INET6,
    INET4_OR_6 = AF_UNSPEC, // It do be like that.
};

enum class AddrInfoSockType : u8 {
    STREAM = SOCK_STREAM,
};
enum class AddrInfoProto : u8 {
    TCP = IPPROTO_TCP,
};

// -

struct SockHints {
    AddrInfoFlags flags = 0;
    AddrInfoFamily family;
    optional<AddrInfoSockType> sock_type;
    optional<AddrInfoProto> proto;
};

// -

struct SockAddr {
    AddrInfoFamily family;
    u16 port;
    u32 flow_label = 0; // Only for ipv6.
    array<u8, 16> addr_bytes = {}; // For ipv4, 4..15 = 0.
    u32 scope_id = 0; // Only for ipv6.

    static from



    span<u8> bytes() const {
        switch (family) {
            case AddrInfoFamily::INET4:
                return span{addr_bytes, 4};
            case AddrInfoFamily::INET6:
                return span{addr_bytes, 16};
        }
        CRASH();
    }
};

struct AddrInfo {
    AddrInfoFlags flags;
    AddrInfoFamily family;
    AddrInfoSockType sock_type;
    AddrInfoProto proto;
    string canonname;
    SockAddr addr;

    static AddrInfo from(const addrinfo& raw) {
        auto ret = AddrInfo{
            .flags = raw.ai_flags,
            .family = raw.ai_family,
            .sock_type = raw.ai_socktype,
            .proto = raw.ai_protocol,
            .flags = raw.ai_flags,
            .canonname = raw.ai_canonname,
            .addr = {},
        };
        let& p_sockaddr = raw.ai_addr;
        switch (raw.ai_addrlen) {
        case sizeof(sockaddr_in):
            let& addr = *reinterpret_cast<const sockaddr_in*>(p_sockaddr);
            ret.addr = {
                .family = addr.sin_family, // ;)
                .port = addr.sin_port,
                .flow_label = 0,
                .addr_bytes = {},
            };
            memcpy(cur.addr.addr_bytes.data(), &addr.sin_addr, sizeof(addr.sin_addr));
            break;

        case sizeof(sockaddr_in6):
            let& addr = *reinterpret_cast<const sockaddr_in6*>(p_sockaddr);
            cur.addr = {
                .family = addr.sin6_family,
                .port = addr.sin6_port,
                .flow_label = addr.sin6_flowinfo,
                .addr_bytes = {},
                .scope_id = addr.sin6_scope_id,
            };
            memcpy(cur.addr.addr_bytes.data(), &addr.sin6_addr, sizeof(addr.sin6_addr));
            break;

        default: // wtf?
            CRASH();
        }
        return ret;
    }
};





























// -

namespace winsock {

class Winsock {
public:
    Winsock() {
        WSADATA wsaData;
        if (const auto err = WSAStartup(MAKEWORD(2,2), &wsaData)) {
            fprintf(stderr, "WSAStartup() -> %i\n", err);
            std::abort();
        }
    }
    ~Winsock() {
        WSACleanup();
    }
};
static const auto s_winsock = Winsock();

// -

#ifndef WSAAPI
#define WSAAPI
#endif

SOCKET WSAAPI socket(
  int af,
  int type,
  int protocol
);

class Socket_Winsock : public Socket {

    template<class T>
    static auto
}

enum class SocketShutdown {
    Receive = SD_RECEIVE,
    Send = SD_SEND,
    Both = SD_BOTH,
};

struct TraitNoCopy {
    TraitNoCopy(const TraitNoCopy&) = delete;
    TraitNoCopy& operator=(const TraitNoCopy&) = delete;
};

struct TraitNoMove {
    TraitNoCopy(const TraitNoCopy&) = delete;
    TraitNoCopy& operator=(const TraitNoCopy&) = delete;
};

struct TraitNoCopyNoMove : public TraitNoCopy, public TraitNoMove {};

class SocketLib : public TraitNoCopyNoMove {
private:
    static mutex load_mutex;
    static std::weak_ptr<SocketLib> loaded;
public:
    static std::shared_ptr<SocketLib> load() {
        const auto lock = std::lock_guard{load_mutex};
        if (auto existing = loaded.lock()) return existing;
        auto ret = std::make_shared<SocketLib>(PrivateCallchain{});
        loaded = ret;
        return ret;
    }

private:
    struct PrivateCallchain{};
public:
    SocketLib(PrivateCallchain) = default;
    ~SocketLib() = default;

    Socket create_socket(const AddrInfo& addr) const {
        auto ret = Socket{socket(to_underlying(addr.family), to_underlying(addr.sock_type), to_underlying(addr.proto))};
        return ret;
    }

    optional<vector<AddrInfo>> get_addr_info(const string* const node_or_host, const string* const service_or_port, const SockHints& hints) {
        auto hints2 = addrinfo{}
        hints2.flags = to_underlying(hints.flags);
        hints2.family = to_underlying(hints.family);
        hints2.sock_type = hints.sock_type ? to_underlying(*hints.sock_type) : 0;
        hints2.proto = hints.proto ? to_underlying(*hints.proto) : 0;
        const ADDRINFOA* info_root = nullptr;
        let res = getaddrinfo(
            node_or_host ? node_or_host->c_str() : nullptr,
            service_or_port ? service_or_port->c_str() : nullptr,
            &hints2,
            &info_root);
        let information_wants_to_be_freed = scope_exit([&]() {
            if (info_root) {
                freeaddrinfo(info_root);
            }
        });
        if (res) return {}; // 0 is success.

        auto ret = vector<AddrInfo>{};
        auto cur_info = info_root;
        while (cur_info) {
            auto cur = AddrInfo::from(*cur_info);
            ret.push_back(cur);
            cur_info = cur_info->ai_next;
        }

        return ret;
    }
};

class Socket : public TraitNoCopy {
public:
    SOCKET raw = INVALID_SOCKET;

    Socket() = default;
    Socket(SOCKET raw) : raw(raw) {}
    ~Socket() {
        close();
    }

    Socket(Socket&& rhs) {
        *this = std::move(rhs);
    }
    auto& operator=(Socket&& rhs) {
        swap(raw, rhs.raw);
        rhs.close();
        return *this;
    }

    explicit operator bool() const {
        return raw != INVALID_SOCKET;
    }

    // -

    bool bind(const SockAddr& addr) const {
        if (!*this) return false;
        let bytes = addr.addr();
        const auto res = ::bind(raw, bytes.data(), bytes.size());
        return res != SOCKET_ERROR;
    }

    bool listen() const {
        if (!*this) return false;
        const auto res = ::listen(raw, SOMAXCONN);
        return res != SOCKET_ERROR;
    }

    Socket accept() const {
        if (!*this) return false;
        auto ret = Socket{::accept(raw, SOMAXCONN)};
        return ret;
    }

    void close() {
        (void)closesocket(raw);
        raw = INVALID_SOCKET;
    }

    bool shutdown(const SocketShutdown how) const {
        const res = ::shutdown(raw, to_underlying(how));
        return res != SOCKET_ERROR;
    }

    optional<span<u8>> recv(const span<u8>& dest, const int flags) const {
        const auto res = ::recv(raw, dest.data(), dest.size(), flags);
        if (res == SOCKET_ERROR) {
            const auto err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) return dest.subspan(0,0);
            return {};
        }
        if (!res) { // Closed.
            return {};
        }
        ASSERT(res > 0);
        const auto received = dest.subspan(0, res);
        return received;
    }

    optional<span<const u8>> send(const span<const u8>& src, const int flags) const {
        const auto res = ::send(raw, src.data(), src.size(), flags);
        if (res == SOCKET_ERROR) {
            return {};
        }
        if (!res) { // Closed.
            return {};
        }
        ASSERT(res > 0);
        const auto unsent = dest.subspan(res);
        return unsent;
    }
};

static std::atomic<bool> s_did_init_winsock;
static std::
static auto s_winsock_cleanup = scope_exit([&]() {
    if (!s_did_init_winsock.load()) return;

});


enum class AddrInfoFlags {

};

struct AddrInfo {

};

GetAddrInfo(const std::string& node_name, const std::string& service_name, )
GetAddrInfoW

} // namespace yote



class Socket {


   static Socket Create(

};

    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
