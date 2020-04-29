#ifndef _UVW_SINGLE_HTPP
#define _UVW_SINGLE_HTPP
/*-- #include "uvw.hpp" start --*/
/*-- #include "uvw/async.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/

#include <cstddef>
#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/resource.hpp" start --*/

#include <memory>
#include <utility>
/*-- #include "uvw/emitter.hpp" start --*/

#include <algorithm>
#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <type_traits>
#include <utility>
#include <uv.h>
#include <vector>

namespace uvw
{

    /**
     * @brief The ErrorEvent event.
     *
     * Custom wrapper around error constants of `libuv`.
     */
    struct ErrorEvent
    {
        template<typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
        explicit ErrorEvent(U val) noexcept : ec{ static_cast<int>(val) }
        {
        }

        /**
         * @brief Returns the `libuv` error code equivalent to the given platform
         * dependent error code.
         *
         * It returns:
         * * POSIX error codes on Unix (the ones stored in errno).
         * * Win32 error codes on Windows (those returned by GetLastError() or
         * WSAGetLastError()).
         *
         * If `sys` is already a `libuv` error code, it is simply returned.
         *
         * @param sys A platform dependent error code.
         * @return The `libuv` error code equivalent to the given platform dependent
         * error code.
         */
        static int translate(int sys) noexcept
        {
            return uv_translate_sys_error(sys);
        }

        /**
         * @brief Returns the error message for the given error code.
         *
         * Leaks a few bytes of memory when you call it with an unknown error code.
         *
         * @return The error message for the given error code.
         */
        const char *what() const noexcept
        {
            return uv_strerror(ec);
        }

        /**
         * @brief Returns the error name for the given error code.
         *
         * Leaks a few bytes of memory when you call it with an unknown error code.
         *
         * @return The error name for the given error code.
         */
        const char *name() const noexcept
        {
            return uv_err_name(ec);
        }

        /**
         * @brief Gets the underlying error code, that is an error constant of
         * `libuv`.
         * @return The underlying error code.
         */
        int code() const noexcept
        {
            return ec;
        }

        /**
         * @brief Checks if the event contains a valid error code.
         * @return True in case of success, false otherwise.
         */
        explicit operator bool() const noexcept
        {
            return ec < 0;
        }

      private:
        const int ec;
    };

    /**
     * @brief Event emitter base class.
     *
     * Almost everything in `uvw` is an event emitter.<br/>
     * This is the base class from which resources and loops inherit.
     */
    template<typename T>
    class Emitter
    {
        struct BaseHandler
        {
            virtual ~BaseHandler() noexcept = default;
            virtual bool empty() const noexcept = 0;
            virtual void clear() noexcept = 0;
        };

        template<typename E>
        struct Handler final : BaseHandler
        {
            using Listener = std::function<void(E &, T &)>;
            using Element = std::pair<bool, Listener>;
            using ListenerList = std::list<Element>;
            using Connection = typename ListenerList::iterator;

            bool empty() const noexcept override
            {
                auto pred = [](auto &&element) {
                    return element.first;
                };

                return std::all_of(onceL.cbegin(), onceL.cend(), pred) && std::all_of(onL.cbegin(), onL.cend(), pred);
            }

            void clear() noexcept override
            {
                if (publishing)
                {
                    auto func = [](auto &&element) {
                        element.first = true;
                    };
                    std::for_each(onceL.begin(), onceL.end(), func);
                    std::for_each(onL.begin(), onL.end(), func);
                }
                else
                {
                    onceL.clear();
                    onL.clear();
                }
            }

            Connection once(Listener f)
            {
                return onceL.emplace(onceL.cend(), false, std::move(f));
            }

            Connection on(Listener f)
            {
                return onL.emplace(onL.cend(), false, std::move(f));
            }

            void erase(Connection conn) noexcept
            {
                conn->first = true;

                if (!publishing)
                {
                    auto pred = [](auto &&element) {
                        return element.first;
                    };
                    onceL.remove_if(pred);
                    onL.remove_if(pred);
                }
            }

            void publish(E event, T &ref)
            {
                ListenerList currentL;
                onceL.swap(currentL);

                auto func = [&event, &ref](auto &&element) {
                    return element.first ? void() : element.second(event, ref);
                };

                publishing = true;

                std::for_each(onL.rbegin(), onL.rend(), func);
                std::for_each(currentL.rbegin(), currentL.rend(), func);

                publishing = false;

                onL.remove_if([](auto &&element) { return element.first; });
            }

          private:
            bool publishing{ false };
            ListenerList onceL{};
            ListenerList onL{};
        };

        static std::size_t next_type() noexcept
        {
            static std::size_t counter = 0;
            return counter++;
        }

        template<typename>
        static std::size_t event_type() noexcept
        {
            static std::size_t value = next_type();
            return value;
        }

        template<typename E>
        Handler<E> &handler() noexcept
        {
            std::size_t type = event_type<E>();

            if (!(type < handlers.size()))
            {
                handlers.resize(type + 1);
            }

            if (!handlers[type])
            {
                handlers[type] = std::make_unique<Handler<E>>();
            }

            return static_cast<Handler<E> &>(*handlers[type]);
        }

      protected:
        template<typename E>
        void publish(E event)
        {
            handler<E>().publish(std::move(event), *static_cast<T *>(this));
        }

      public:
        template<typename E>
        using Listener = typename Handler<E>::Listener;

        /**
         * @brief Connection type for a given event type.
         *
         * Given an event type `E`, `Connection<E>` is the type of the connection
         * object returned by the event emitter whenever a listener for the given
         * type is registered.
         */
        template<typename E>
        struct Connection : private Handler<E>::Connection
        {
            template<typename>
            friend class Emitter;

            Connection() = default;
            Connection(const Connection &) = default;
            Connection(Connection &&) = default;

            Connection(typename Handler<E>::Connection conn) : Handler<E>::Connection{ std::move(conn) }
            {
            }

            Connection &operator=(const Connection &) = default;
            Connection &operator=(Connection &&) = default;
        };

        virtual ~Emitter() noexcept
        {
            static_assert(std::is_base_of_v<Emitter<T>, T>);
        }

        /**
         * @brief Registers a long-lived listener with the event emitter.
         *
         * This method can be used to register a listener that is meant to be
         * invoked more than once for the given event type.<br/>
         * The Connection object returned by the method can be freely discarded. It
         * can be used later to disconnect the listener, if needed.
         *
         * Listener is usually defined as a callable object assignable to a
         * `std::function<void(const E &, T &)`, where `E` is the type of the event
         * and `T` is the type of the resource.
         *
         * @param f A valid listener to be registered.
         * @return Connection object to be used later to disconnect the listener.
         */
        template<typename E>
        Connection<E> on(Listener<E> f)
        {
            return handler<E>().on(std::move(f));
        }

        /**
         * @brief Registers a short-lived listener with the event emitter.
         *
         * This method can be used to register a listener that is meant to be
         * invoked only once for the given event type.<br/>
         * The Connection object returned by the method can be freely discarded. It
         * can be used later to disconnect the listener, if needed.
         *
         * Listener is usually defined as a callable object assignable to a
         * `std::function<void(const E &, T &)`, where `E` is the type of the event
         * and `T` is the type of the resource.
         *
         * @param f A valid listener to be registered.
         * @return Connection object to be used later to disconnect the listener.
         */
        template<typename E>
        Connection<E> once(Listener<E> f)
        {
            return handler<E>().once(std::move(f));
        }

        /**
         * @brief Disconnects a listener from the event emitter.
         * @param conn A valid Connection object
         */
        template<typename E>
        void erase(Connection<E> conn) noexcept
        {
            handler<E>().erase(std::move(conn));
        }

        /**
         * @brief Disconnects all the listeners for the given event type.
         */
        template<typename E>
        void clear() noexcept
        {
            handler<E>().clear();
        }

        /**
         * @brief Disconnects all the listeners.
         */
        void clear() noexcept
        {
            std::for_each(handlers.begin(), handlers.end(), [](auto &&hdlr) {
                if (hdlr)
                {
                    hdlr->clear();
                }
            });
        }

        /**
         * @brief Checks if there are listeners registered for the specific event.
         * @return True if there are no listeners registered for the specific event,
         * false otherwise.
         */
        template<typename E>
        bool empty() const noexcept
        {
            std::size_t type = event_type<E>();

            return (!(type < handlers.size()) || !handlers[type] || static_cast<Handler<E> &>(*handlers[type]).empty());
        }

        /**
         * @brief Checks if there are listeners registered with the event emitter.
         * @return True if there are no listeners registered with the event emitter,
         * false otherwise.
         */
        bool empty() const noexcept
        {
            return std::all_of(handlers.cbegin(), handlers.cend(), [](auto &&hdlr) { return !hdlr || hdlr->empty(); });
        }

      private:
        std::vector<std::unique_ptr<BaseHandler>> handlers{};
    };

} // namespace uvw

/*-- #include "uvw/emitter.hpp" end --*/
/*-- #include "uvw/underlying_type.hpp" start --*/

#include <memory>
#include <type_traits>
#include <utility>
/*-- #include "uvw/loop.hpp" start --*/

#ifdef _WIN32
    #include <ciso646>
#endif

#include <chrono>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/emitter.hpp" start --*/
/*-- #include "uvw/emitter.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <uv.h>
#include <vector>

namespace uvw
{

    namespace details
    {

        enum class UVHandleType : std::underlying_type_t<uv_handle_type>
        {
            UNKNOWN = UV_UNKNOWN_HANDLE,
            ASYNC = UV_ASYNC,
            CHECK = UV_CHECK,
            FS_EVENT = UV_FS_EVENT,
            FS_POLL = UV_FS_POLL,
            HANDLE = UV_HANDLE,
            IDLE = UV_IDLE,
            PIPE = UV_NAMED_PIPE,
            POLL = UV_POLL,
            PREPARE = UV_PREPARE,
            PROCESS = UV_PROCESS,
            STREAM = UV_STREAM,
            TCP = UV_TCP,
            TIMER = UV_TIMER,
            TTY = UV_TTY,
            UDP = UV_UDP,
            SIGNAL = UV_SIGNAL,
            FILE = UV_FILE
        };

        template<typename T>
        struct UVTypeWrapper
        {
            using Type = T;

            constexpr UVTypeWrapper() : value{}
            {
            }
            constexpr UVTypeWrapper(Type val) : value{ val }
            {
            }

            constexpr operator Type() const noexcept
            {
                return value;
            }

            bool operator==(UVTypeWrapper other) const noexcept
            {
                return value == other.value;
            }

          private:
            const Type value;
        };

        template<typename T>
        bool operator==(UVTypeWrapper<T> lhs, UVTypeWrapper<T> rhs)
        {
            return !(lhs == rhs);
        }

    } // namespace details

    /**
     * @brief Utility class to handle flags.
     *
     * This class can be used to handle flags of a same enumeration type.<br/>
     * It is meant to be used as an argument for functions and member methods and
     * as part of events.<br/>
     * `Flags<E>` objects can be easily _or-ed_ and _and-ed_ with other instances of
     * the same type or with instances of the type `E` (that is, the actual flag
     * type), thus converted to the underlying type when needed.
     */
    template<typename E>
    class Flags final
    {
        using InnerType = std::underlying_type_t<E>;

        constexpr InnerType toInnerType(E flag) const noexcept
        {
            return static_cast<InnerType>(flag);
        }

      public:
        using Type = InnerType;

        /**
         * @brief Utility factory method to pack a set of values all at once.
         * @return A valid instance of Flags instantiated from values `V`.
         */
        template<E... V>
        static constexpr Flags<E> from()
        {
            return (Flags<E>{} | ... | V);
        }

        /**
         * @brief Constructs a Flags object from a value of the enum `E`.
         * @param flag A value of the enum `E`.
         */
        constexpr Flags(E flag) noexcept : flags{ toInnerType(flag) }
        {
        }

        /**
         * @brief Constructs a Flags object from an instance of the underlying type
         * of the enum `E`.
         * @param f An instance of the underlying type of the enum `E`.
         */
        constexpr Flags(Type f) : flags{ f }
        {
        }

        /**
         * @brief Constructs an uninitialized Flags object.
         */
        constexpr Flags() : flags{}
        {
        }

        constexpr Flags(const Flags &f) noexcept : flags{ f.flags }
        {
        }
        constexpr Flags(Flags &&f) noexcept : flags{ std::move(f.flags) }
        {
        }

        ~Flags() noexcept
        {
            static_assert(std::is_enum_v<E>);
        }

        constexpr Flags &operator=(const Flags &f) noexcept
        {
            flags = f.flags;
            return *this;
        }

        constexpr Flags &operator=(Flags &&f) noexcept
        {
            flags = std::move(f.flags);
            return *this;
        }

        /**
         * @brief Or operator.
         * @param f A valid instance of Flags.
         * @return This instance _or-ed_ with `f`.
         */
        constexpr Flags operator|(const Flags &f) const noexcept
        {
            return Flags{ flags | f.flags };
        }

        /**
         * @brief Or operator.
         * @param flag A value of the enum `E`.
         * @return This instance _or-ed_ with `flag`.
         */
        constexpr Flags operator|(E flag) const noexcept
        {
            return Flags{ flags | toInnerType(flag) };
        }

        /**
         * @brief And operator.
         * @param f A valid instance of Flags.
         * @return This instance _and-ed_ with `f`.
         */
        constexpr Flags operator&(const Flags &f) const noexcept
        {
            return Flags{ flags & f.flags };
        }

        /**
         * @brief And operator.
         * @param flag A value of the enum `E`.
         * @return This instance _and-ed_ with `flag`.
         */
        constexpr Flags operator&(E flag) const noexcept
        {
            return Flags{ flags & toInnerType(flag) };
        }

        /**
         * @brief Checks if this instance is initialized.
         * @return False if it's uninitialized, true otherwise.
         */
        explicit constexpr operator bool() const noexcept
        {
            return !(flags == InnerType{});
        }

        /**
         * @brief Casts the instance to the underlying type of `E`.
         * @return An integral representation of the contained flags.
         */
        constexpr operator Type() const noexcept
        {
            return flags;
        }

      private:
        InnerType flags;
    };

    /**
     * @brief Windows size representation.
     */
    struct WinSize
    {
        int width;  /*!< The _width_ of the given window. */
        int height; /*!< The _height_ of the given window. */
    };

    using HandleType = details::UVHandleType; /*!< The type of a handle. */

    using HandleCategory = details::UVTypeWrapper<uv_handle_type>; /*!< Utility class that wraps an
                                                                      internal handle type. */
    using FileHandle = details::UVTypeWrapper<uv_file>;            /*!< Utility class that wraps an internal
                                                                      file handle. */
    using OSSocketHandle = details::UVTypeWrapper<uv_os_sock_t>;   /*!< Utility class that wraps an os
                                                                      socket handle. */
    using OSFileDescriptor = details::UVTypeWrapper<uv_os_fd_t>;   /*!< Utility class that wraps an os file
                                                                      descriptor. */
    using PidType = details::UVTypeWrapper<uv_pid_t>;              /*!< Utility class that wraps a cross
                                                                      platform representation of a pid. */

    constexpr FileHandle StdIN{ 0 };  /*!< Placeholder for stdin descriptor. */
    constexpr FileHandle StdOUT{ 1 }; /*!< Placeholder for stdout descriptor. */
    constexpr FileHandle StdERR{ 2 }; /*!< Placeholder for stderr descriptor. */

    using TimeSpec = uv_timespec_t; /*!< Library equivalent for uv_timespec_t. */
    using Stat = uv_stat_t;         /*!< Library equivalent for uv_stat_t. */
    using Statfs = uv_statfs_t;     /*!< Library equivalent for uv_statfs_t. */
    using Uid = uv_uid_t;           /*!< Library equivalent for uv_uid_t. */
    using Gid = uv_gid_t;           /*!< Library equivalent for uv_gid_t. */

    using TimeVal = uv_timeval_t;     /*!< Library equivalent for uv_timeval_t. */
    using TimeVal64 = uv_timeval64_t; /*!< Library equivalent for uv_timeval64_t. */
    using RUsage = uv_rusage_t;       /*!< Library equivalent for uv_rusage_t. */

    /**
     * @brief Utility class.
     *
     * This class can be used to query the subset of the password file entry for the
     * current effective uid (not the real uid).
     *
     * \sa Utilities::passwd
     */
    struct Passwd
    {
        Passwd(std::shared_ptr<uv_passwd_t> pwd) : passwd{ pwd }
        {
        }

        /**
         * @brief Gets the username.
         * @return The username of the current effective uid (not the real uid).
         */
        std::string username() const noexcept
        {
            return ((passwd && passwd->username) ? passwd->username : "");
        }

        /**
         * @brief Gets the uid.
         * @return The current effective uid (not the real uid).
         */
        auto uid() const noexcept
        {
            return (passwd ? passwd->uid : decltype(uv_passwd_t::uid){});
        }

        /**
         * @brief Gets the gid.
         * @return The gid of the current effective uid (not the real uid).
         */
        auto gid() const noexcept
        {
            return (passwd ? passwd->gid : decltype(uv_passwd_t::gid){});
        }

        /**
         * @brief Gets the shell.
         * @return The shell of the current effective uid (not the real uid).
         */
        std::string shell() const noexcept
        {
            return ((passwd && passwd->shell) ? passwd->shell : "");
        }

        /**
         * @brief Gets the homedir.
         * @return The homedir of the current effective uid (not the real uid).
         */
        std::string homedir() const noexcept
        {
            return ((passwd && passwd->homedir) ? passwd->homedir : "");
        }

        /**
         * @brief Checks if the instance contains valid data.
         * @return True if data are all valid, false otherwise.
         */
        operator bool() const noexcept
        {
            return static_cast<bool>(passwd);
        }

      private:
        std::shared_ptr<uv_passwd_t> passwd;
    };

    /**
     * @brief Utility class.
     *
     * This class can be used to get name and information about the current kernel.
     * The populated data includes the operating system name, release, version, and
     * machine.
     *
     * \sa Utilities::uname
     */
    struct UtsName
    {
        UtsName(std::shared_ptr<uv_utsname_t> utsname) : utsname{ utsname }
        {
        }

        /**
         * @brief Gets the operating system name (like "Linux").
         * @return The operating system name.
         */
        std::string sysname() const noexcept
        {
            return utsname ? utsname->sysname : "";
        }

        /**
         * @brief Gets the operating system release (like "2.6.28").
         * @return The operating system release.
         */
        std::string release() const noexcept
        {
            return utsname ? utsname->release : "";
        }

        /**
         * @brief Gets the operating system version.
         * @return The operating system version
         */
        std::string version() const noexcept
        {
            return utsname ? utsname->version : "";
        }

        /**
         * @brief Gets the hardware identifier.
         * @return The hardware identifier.
         */
        std::string machine() const noexcept
        {
            return utsname ? utsname->machine : "";
        }

      private:
        std::shared_ptr<uv_utsname_t> utsname;
    };

    /**
     * @brief The IPv4 tag.
     *
     * To be used as template parameter to switch between IPv4 and IPv6.
     */
    struct IPv4
    {
    };

    /**
     * @brief The IPv6 tag.
     *
     * To be used as template parameter to switch between IPv4 and IPv6.
     */
    struct IPv6
    {
    };

    /**
     * @brief Address representation.
     */
    struct Addr
    {
        std::string ip;    /*!< Either an IPv4 or an IPv6. */
        unsigned int port; /*!< A valid service identifier. */
    };

    /**
     * \brief CPU information.
     */
    struct CPUInfo
    {
        using CPUTime = decltype(uv_cpu_info_t::cpu_times);

        std::string model; /*!< The model of the CPU. */
        int speed;         /*!< The frequency of the CPU. */

        /**
         * @brief CPU times.
         *
         * It is built up of the following data members: `user`, `nice`, `sys`,
         * `idle`, `irq`, all of them having type `uint64_t`.
         */
        CPUTime times;
    };

    /**
     * \brief Interface address.
     */
    struct InterfaceAddress
    {
        std::string name; /*!< The name of the interface (as an example _eth0_). */
        char physical[6]; /*!< The physical address. */
        bool internal;    /*!< True if it is an internal interface (as an example
                             _loopback_), false otherwise. */
        Addr address;     /*!< The address of the given interface. */
        Addr netmask;     /*!< The netmask of the given interface. */
    };

    namespace details
    {

        static constexpr std::size_t DEFAULT_SIZE = 128;

        template<typename>
        struct IpTraits;

        template<>
        struct IpTraits<IPv4>
        {
            using Type = sockaddr_in;
            using AddrFuncType = int (*)(const char *, int, Type *);
            using NameFuncType = int (*)(const Type *, char *, std::size_t);
            static constexpr AddrFuncType addrFunc = &uv_ip4_addr;
            static constexpr NameFuncType nameFunc = &uv_ip4_name;
            static constexpr auto sinPort(const Type *addr)
            {
                return addr->sin_port;
            }
        };

        template<>
        struct IpTraits<IPv6>
        {
            using Type = sockaddr_in6;
            using AddrFuncType = int (*)(const char *, int, Type *);
            using NameFuncType = int (*)(const Type *, char *, std::size_t);
            static constexpr AddrFuncType addrFunc = &uv_ip6_addr;
            static constexpr NameFuncType nameFunc = &uv_ip6_name;
            static constexpr auto sinPort(const Type *addr)
            {
                return addr->sin6_port;
            }
        };

        template<typename I>
        Addr address(const typename details::IpTraits<I>::Type *aptr) noexcept
        {
            Addr addr;
            char name[DEFAULT_SIZE];

            int err = details::IpTraits<I>::nameFunc(aptr, name, DEFAULT_SIZE);

            if (0 == err)
            {
                addr.port = ntohs(details::IpTraits<I>::sinPort(aptr));
                addr.ip = std::string{ name };
            }

            return addr;
        }

        template<typename I, typename F, typename H>
        Addr address(F &&f, const H *handle) noexcept
        {
            sockaddr_storage ssto;
            int len = sizeof(ssto);
            Addr addr{};

            int err = std::forward<F>(f)(handle, reinterpret_cast<sockaddr *>(&ssto), &len);

            if (0 == err)
            {
                typename IpTraits<I>::Type *aptr = reinterpret_cast<typename IpTraits<I>::Type *>(&ssto);
                addr = address<I>(aptr);
            }

            return addr;
        }

        template<typename F, typename... Args>
        std::string tryRead(F &&f, Args &&... args) noexcept
        {
            std::size_t size = DEFAULT_SIZE;
            char buf[DEFAULT_SIZE];
            std::string str{};
            auto err = std::forward<F>(f)(args..., buf, &size);

            if (UV_ENOBUFS == err)
            {
                std::unique_ptr<char[]> data{ new char[size] };
                err = std::forward<F>(f)(args..., data.get(), &size);

                if (0 == err)
                {
                    str = data.get();
                }
            }
            else if (0 == err)
            {
                str.assign(buf, size);
            }

            return str;
        }

    } // namespace details

    /**
     * @brief Miscellaneous utilities.
     *
     * Miscellaneous functions that don’t really belong to any other class.
     */
    struct Utilities
    {
        using MallocFuncType = void *(*) (size_t);
        using ReallocFuncType = void *(*) (void *, size_t);
        using CallocFuncType = void *(*) (size_t, size_t);
        using FreeFuncType = void (*)(void *);

        /**
         * @brief OS dedicated utilities.
         */
        struct OS
        {
            /**
             * @brief Returns the current process id.
             *
             * See the official
             * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_os_getpid)
             * for further details.
             *
             * @return The current process id.
             */
            static PidType pid() noexcept
            {
                return uv_os_getpid();
            }

            /**
             * @brief Returns the parent process id.
             *
             * See the official
             * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_os_getppid)
             * for further details.
             *
             * @return The parent process id.
             */
            static PidType parent() noexcept
            {
                return uv_os_getppid();
            }

            /**
             * @brief Gets the current user's home directory.
             *
             * See the official
             * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_os_homedir)
             * for further details.
             *
             * @return The current user's home directory, an empty string in case of
             * errors.
             */
            static std::string homedir() noexcept
            {
                return details::tryRead(&uv_os_homedir);
            }

            /**
             * @brief Gets the temp directory.
             *
             * See the official
             * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_os_tmpdir)
             * for further details.
             *
             * @return The temp directory, an empty string in case of errors.
             */
            static std::string tmpdir() noexcept
            {
                return details::tryRead(&uv_os_tmpdir);
            }

            /**
             * @brief Retrieves an environment variable.
             * @param name The name of the variable to be retrieved.
             * @return The value of the environment variable, an empty string in
             * case of errors.
             */
            static std::string env(const std::string &name) noexcept
            {
                return details::tryRead(&uv_os_getenv, name.c_str());
            }

            /**
             * @brief Creates, updates or deletes an environment variable.
             * @param name The name of the variable to be updated.
             * @param value The value to be used for the variable (an empty string
             * to unset it).
             * @return True in case of success, false otherwise.
             */
            static bool env(const std::string &name, const std::string &value) noexcept
            {
                return (0 == (value.empty() ? uv_os_unsetenv(name.c_str()) : uv_os_setenv(name.c_str(), value.c_str())));
            }

            /**
             * @brief Retrieves all environment variables and iterates them.
             *
             * Environment variables are passed one at a time to the callback in the
             * form of `std::string_view`s.<br/>
             * The signature of the function call operator must be such that it
             * accepts two parameters, the name and the value of the i-th variable.
             *
             * @tparam Func Type of a function object to which to pass environment
             * variables.
             * @param func A function object to which to pass environment variables.
             * @return True in case of success, false otherwise.
             */
            template<typename Func>
            static std::enable_if_t<std::is_invocable_v<Func, std::string_view, std::string_view>, bool> env(Func func) noexcept
            {
                uv_env_item_t *items = nullptr;
                int count{};

                const bool ret = (uv_os_environ(&items, &count) == 0);

                if (ret)
                {
                    for (int pos = 0; pos < count; ++pos)
                    {
                        func(std::string_view{ items[pos].name }, std::string_view{ items[pos].value });
                    }

                    uv_os_free_environ(items, count);
                }

                return ret;
            }

            /**
             * @brief Returns the hostname.
             * @return The hostname, an empty string in case of errors.
             */
            static std::string hostname() noexcept
            {
                return details::tryRead(&uv_os_gethostname);
            }

            /**
             * @brief Gets name and information about the current kernel.
             *
             * This function can be used to get name and information about the
             * current kernel. The populated data includes the operating system
             * name, release, version, and machine.
             *
             * @return Name and information about the current kernel.
             */
            static UtsName uname() noexcept
            {
                auto ptr = std::make_shared<uv_utsname_t>();
                uv_os_uname(ptr.get());
                return ptr;
            }

            /**
             * @brief Gets a subset of the password file entry.
             *
             * This function can be used to get the subset of the password file
             * entry for the current effective uid (not the real uid).
             *
             * See the official
             * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_os_get_passwd)
             * for further details.
             *
             * @return The accessible subset of the password file entry.
             */
            static Passwd passwd() noexcept
            {
                auto deleter = [](uv_passwd_t *passwd) {
                    uv_os_free_passwd(passwd);
                    delete passwd;
                };

                std::shared_ptr<uv_passwd_t> ptr{ new uv_passwd_t, std::move(deleter) };
                uv_os_get_passwd(ptr.get());
                return ptr;
            }
        };

        /**
         * @brief Retrieves the scheduling priority of a process.
         *
         * The returned value is between -20 (high priority) and 19 (low priority).
         * A value that is out of range is returned in case of errors.
         *
         * @note
         * On Windows, the result won't equal necessarily the exact value of the
         * priority because of a mapping to a Windows priority class.
         *
         * @param pid A valid process id.
         * @return The scheduling priority of the process.
         */
        static int osPriority(PidType pid)
        {
            int prio = 0;

            if (uv_os_getpriority(pid, &prio))
            {
                prio = UV_PRIORITY_LOW + 1;
            }

            return prio;
        }

        /**
         * @brief Sets the scheduling priority of a process.
         *
         * The returned value range is between -20 (high priority) and 19 (low
         * priority).
         *
         * @note
         * On Windows, the priority is mapped to a Windows priority class. When
         * retrieving the process priority, the result won't equal necessarily the
         * exact value of the priority.
         *
         * @param pid A valid process id.
         * @param prio The scheduling priority to set to the process.
         * @return True in case of success, false otherwise.
         */
        static bool osPriority(PidType pid, int prio)
        {
            return 0 == uv_os_setpriority(pid, prio);
        }

        /**
         * @brief Gets the type of the handle given a category.
         * @param category A properly initialized handle category.
         * @return The actual type of the handle as defined by HandleType
         */
        static HandleType guessHandle(HandleCategory category) noexcept
        {
            switch (category)
            {
                case UV_ASYNC: return HandleType::ASYNC;
                case UV_CHECK: return HandleType::CHECK;
                case UV_FS_EVENT: return HandleType::FS_EVENT;
                case UV_FS_POLL: return HandleType::FS_POLL;
                case UV_HANDLE: return HandleType::HANDLE;
                case UV_IDLE: return HandleType::IDLE;
                case UV_NAMED_PIPE: return HandleType::PIPE;
                case UV_POLL: return HandleType::POLL;
                case UV_PREPARE: return HandleType::PREPARE;
                case UV_PROCESS: return HandleType::PROCESS;
                case UV_STREAM: return HandleType::STREAM;
                case UV_TCP: return HandleType::TCP;
                case UV_TIMER: return HandleType::TIMER;
                case UV_TTY: return HandleType::TTY;
                case UV_UDP: return HandleType::UDP;
                case UV_SIGNAL: return HandleType::SIGNAL;
                case UV_FILE: return HandleType::FILE;
                default: return HandleType::UNKNOWN;
            }
        }

        /**
         * @brief Gets the type of the stream to be used with the given descriptor.
         *
         * Returns the type of stream that should be used with a given file
         * descriptor.<br/>
         * Usually this will be used during initialization to guess the type of the
         * stdio streams.
         *
         * @param file A valid descriptor.
         * @return One of the following types:
         *
         * * `HandleType::UNKNOWN`
         * * `HandleType::PIPE`
         * * `HandleType::TCP`
         * * `HandleType::TTY`
         * * `HandleType::UDP`
         * * `HandleType::FILE`
         */
        static HandleType guessHandle(FileHandle file) noexcept
        {
            HandleCategory category = uv_guess_handle(file);
            return guessHandle(category);
        }

        /** @brief Gets information about the CPUs on the system.
         *
         * This function can be used to query the underlying system and get a set of
         * descriptors of all the available CPUs.
         *
         * @return A set of descriptors of all the available CPUs.
         */
        static std::vector<CPUInfo> cpuInfo() noexcept
        {
            std::vector<CPUInfo> cpuinfos;

            uv_cpu_info_t *infos;
            int count;

            if (0 == uv_cpu_info(&infos, &count))
            {
                std::for_each(infos, infos + count, [&cpuinfos](const auto &info) {
                    cpuinfos.push_back({ info.model, info.speed, info.cpu_times });
                });

                uv_free_cpu_info(infos, count);
            }

            return cpuinfos;
        }

        /**
         * @brief Gets a set of descriptors of all the available interfaces.
         *
         * This function can be used to query the underlying system and get a set of
         * descriptors of all the available interfaces, either internal or not.
         *
         * @return A set of descriptors of all the available interfaces.
         */
        static std::vector<InterfaceAddress> interfaceAddresses() noexcept
        {
            std::vector<InterfaceAddress> interfaces;

            uv_interface_address_t *ifaces{ nullptr };
            int count{ 0 };

            if (0 == uv_interface_addresses(&ifaces, &count))
            {
                std::for_each(ifaces, ifaces + count, [&interfaces](const auto &iface) {
                    InterfaceAddress interfaceAddress;

                    interfaceAddress.name = iface.name;
                    std::copy(iface.phys_addr, (iface.phys_addr + 6), interfaceAddress.physical);
                    interfaceAddress.internal = iface.is_internal == 0 ? false : true;

                    if (iface.address.address4.sin_family == AF_INET)
                    {
                        interfaceAddress.address = details::address<IPv4>(&iface.address.address4);
                        interfaceAddress.netmask = details::address<IPv4>(&iface.netmask.netmask4);
                    }
                    else if (iface.address.address4.sin_family == AF_INET6)
                    {
                        interfaceAddress.address = details::address<IPv6>(&iface.address.address6);
                        interfaceAddress.netmask = details::address<IPv6>(&iface.netmask.netmask6);
                    }

                    interfaces.push_back(std::move(interfaceAddress));
                });

                uv_free_interface_addresses(ifaces, count);
            }

            return interfaces;
        }

        /**
         * @brief IPv6-capable implementation of
         * [if_indextoname](https://linux.die.net/man/3/if_indextoname).
         *
         * Mapping between network interface names and indexes.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_if_indextoname)
         * for further details.
         *
         * @param index Network interface index.
         * @return Network interface name.
         */
        static std::string indexToName(unsigned int index) noexcept
        {
            return details::tryRead(&uv_if_indextoname, index);
        }

        /**
         * @brief Retrieves a network interface identifier.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/misc.html#c.uv_if_indextoiid)
         * for further details.
         *
         * @param index Network interface index.
         * @return Network interface identifier.
         */
        static std::string indexToIid(unsigned int index) noexcept
        {
            return details::tryRead(&uv_if_indextoiid, index);
        }

        /**
         * @brief Override the use of some standard library’s functions.
         *
         * Override the use of the standard library’s memory allocation
         * functions.<br/>
         * This method must be invoked before any other `uvw` function is called or
         * after all resources have been freed and thus the underlying library
         * doesn’t reference any allocated memory chunk.
         *
         * If any of the function pointers is _null_, the invokation will fail.
         *
         * @note
         * There is no protection against changing the allocator multiple times. If
         * the user changes it they are responsible for making sure the allocator is
         * changed while no memory was allocated with the previous allocator, or
         * that they are compatible.
         *
         * @param mallocFunc Replacement function for _malloc_.
         * @param reallocFunc Replacement function for _realloc_.
         * @param callocFunc Replacement function for _calloc_.
         * @param freeFunc Replacement function for _free_.
         * @return True in case of success, false otherwise.
         */
        static bool replaceAllocator(MallocFuncType mallocFunc, ReallocFuncType reallocFunc, CallocFuncType callocFunc,
                                     FreeFuncType freeFunc) noexcept
        {
            return (0 == uv_replace_allocator(mallocFunc, reallocFunc, callocFunc, freeFunc));
        }

        /**
         * @brief Gets the load average.
         * @return `[0,0,0]` on Windows (not available), the load average otherwise.
         */
        static std::array<double, 3> loadAverage() noexcept
        {
            std::array<double, 3> avg;
            uv_loadavg(avg.data());
            return avg;
        }

        /**
         * @brief Store the program arguments.
         *
         * Required for getting / setting the process title.
         *
         * @return Arguments that haven't been consumed internally.
         */
        static char **setupArgs(int argc, char **argv)
        {
            return uv_setup_args(argc, argv);
        }

        /**
         * @brief Gets the title of the current process.
         * @return The process title.
         */
        static std::string processTitle()
        {
            std::size_t size = details::DEFAULT_SIZE;
            char buf[details::DEFAULT_SIZE];
            std::string str{};

            if (0 == uv_get_process_title(buf, size))
            {
                str.assign(buf, size);
            }

            return str;
        }

        /**
         * @brief Sets the current process title.
         * @param title The process title to be set.
         * @return True in case of success, false otherwise.
         */
        static bool processTitle(std::string title)
        {
            return (0 == uv_set_process_title(title.c_str()));
        }

        /**
         * @brief Gets memory information (in bytes).
         * @return Memory information.
         */
        static uint64_t totalMemory() noexcept
        {
            return uv_get_total_memory();
        }

        /**
         * @brief Gets the amount of memory available to the process (in bytes).
         *
         * Gets the amount of memory available to the process based on limits
         * imposed by the OS. If there is no such constraint, or the constraint is
         * unknown, `0` is returned.<br/>
         * Note that it is not unusual for this value to be less than or greater
         * than `totalMemory`.
         *
         * @return Amount of memory available to the process.
         */
        static uint64_t constrainedMemory() noexcept
        {
            return uv_get_constrained_memory();
        }

        /**
         * @brief Gets the current system uptime.
         * @return The current system uptime or 0 in case of errors.
         */
        static double uptime() noexcept
        {
            double ret;

            if (0 != uv_uptime(&ret))
            {
                ret = 0;
            }

            return ret;
        }

        /**
         * @brief Gets the resource usage measures for the current process.
         * @return Resource usage measures, zeroes-filled object in case of errors.
         */
        static RUsage rusage() noexcept
        {
            RUsage ru;
            auto err = uv_getrusage(&ru);
            return err ? RUsage{} : ru;
        }

        /**
         * @brief Gets the current high-resolution real time.
         *
         * The time is expressed in nanoseconds. It is relative to an arbitrary time
         * in the past. It is not related to the time of the day and therefore not
         * subject to clock drift. The primary use is for measuring performance
         * between interval.
         *
         * @return The current high-resolution real time.
         */
        static uint64_t hrtime() noexcept
        {
            return uv_hrtime();
        }

        /**
         * @brief Gets the executable path.
         * @return The executable path, an empty string in case of errors.
         */
        static std::string path() noexcept
        {
            return details::tryRead(&uv_exepath);
        }

        /**
         * @brief Gets the current working directory.
         * @return The current working directory, an empty string in case of errors.
         */
        static std::string cwd() noexcept
        {
            return details::tryRead(&uv_cwd);
        }

        /**
         * @brief Changes the current working directory.
         * @param dir The working directory to be set.
         * @return True in case of success, false otherwise.
         */
        static bool chdir(const std::string &dir) noexcept
        {
            return (0 == uv_chdir(dir.data()));
        }

        /**
         * @brief Cross-platform implementation of
         * [`gettimeofday`](https://linux.die.net/man/2/gettimeofday)
         * @return The current time.
         */
        static TimeVal64 timeOfDay() noexcept
        {
            uv_timeval64_t ret;
            uv_gettimeofday(&ret);
            return ret;
        }

        /**
         * @brief Causes the calling thread to sleep for a while.
         * @param msec Number of milliseconds to sleep.
         */
        static void sleep(unsigned int msec) noexcept
        {
            uv_sleep(msec);
        }
    };

} // namespace uvw

/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVLoopOption : std::underlying_type_t<uv_loop_option>
        {
            BLOCK_SIGNAL = UV_LOOP_BLOCK_SIGNAL
        };

        enum class UVRunMode : std::underlying_type_t<uv_run_mode>
        {
            DEFAULT = UV_RUN_DEFAULT,
            ONCE = UV_RUN_ONCE,
            NOWAIT = UV_RUN_NOWAIT
        };

    } // namespace details

    /**
     * @brief Untyped handle class
     *
     * Handles' types are unknown from the point of view of the loop.<br/>
     * Anyway, a loop maintains a list of all the associated handles and let the
     * users walk them as untyped instances.<br/>
     * This can help to end all the pending requests by closing the handles.
     */
    struct BaseHandle
    {
        /**
         * @brief Gets the category of the handle.
         *
         * A base handle offers no functionality to promote it to the actual handle
         * type. By means of this function, an opaque value that identifies the
         * category of the handle is made available to the users.
         *
         * @return The actual category of the handle.
         */
        virtual HandleCategory category() const noexcept = 0;

        /**
         * @brief Gets the type of the handle.
         *
         * A base handle offers no functionality to promote it to the actual handle
         * type. By means of this function, the type of the underlying handle as
         * specified by HandleType is made available to the user.
         *
         * @return The actual type of the handle.
         */
        virtual HandleType type() const noexcept = 0;

        /**
         * @brief Checks if the handle is active.
         *
         * What _active_ means depends on the type of handle:
         *
         * * An AsyncHandle handle is always active and cannot be deactivated,
         * except by closing it with uv_close().
         * * A PipeHandle, TCPHandle, UDPHandle, etc. handle - basically any handle
         * that deals with I/O - is active when it is doing something that involves
         * I/O, like reading, writing, connecting, accepting new connections, etc.
         * * A CheckHandle, IdleHandle, TimerHandle, etc. handle is active when it
         * has been started with a call to `start()`.
         *
         * Rule of thumb: if a handle of type `FooHandle` has a `start()` member
         * method, then it’s active from the moment that method is called. Likewise,
         * `stop()` deactivates the handle again.
         *
         * @return True if the handle is active, false otherwise.
         */
        virtual bool active() const noexcept = 0;

        /**
         * @brief Checks if a handle is closing or closed.
         *
         * This function should only be used between the initialization of the
         * handle and the arrival of the close callback.
         *
         * @return True if the handle is closing or closed, false otherwise.
         */
        virtual bool closing() const noexcept = 0;

        /**
         * @brief Reference the given handle.
         *
         * References are idempotent, that is, if a handle is already referenced
         * calling this function again will have no effect.
         */
        virtual void reference() noexcept = 0;

        /**
         * @brief Unreference the given handle.
         *
         * References are idempotent, that is, if a handle is not referenced calling
         * this function again will have no effect.
         */
        virtual void unreference() noexcept = 0;

        /**
         * @brief Checks if the given handle referenced.
         * @return True if the handle referenced, false otherwise.
         */
        virtual bool referenced() const noexcept = 0;

        /**
         * @brief Request handle to be closed.
         *
         * This **must** be called on each handle before memory is released.<br/>
         * In-progress requests are cancelled and this can result in an ErrorEvent
         * emitted.
         */
        virtual void close() noexcept = 0;
    };

    /**
     * @brief The Loop class.
     *
     * The event loop is the central part of `uvw`'s functionalities, as well as
     * `libuv`'s ones.<br/>
     * It takes care of polling for I/O and scheduling callbacks to be run based on
     * different sources of events.
     */
    class Loop final
        : public Emitter<Loop>
        , public std::enable_shared_from_this<Loop>
    {
        using Deleter = void (*)(uv_loop_t *);

        template<typename, typename>
        friend class Resource;

        Loop(std::unique_ptr<uv_loop_t, Deleter> ptr) noexcept : loop{ std::move(ptr) }
        {
        }

      public:
        using Time = std::chrono::duration<uint64_t, std::milli>;
        using Configure = details::UVLoopOption;
        using Mode = details::UVRunMode;

        /**
         * @brief Initializes a new Loop instance.
         * @return A pointer to the newly created loop.
         */
        static std::shared_ptr<Loop> create()
        {
            auto ptr = std::unique_ptr<uv_loop_t, Deleter>{ new uv_loop_t, [](uv_loop_t *l) {
                                                               delete l;
                                                           } };
            auto loop = std::shared_ptr<Loop>{ new Loop{ std::move(ptr) } };

            if (uv_loop_init(loop->loop.get()))
            {
                loop = nullptr;
            }

            return loop;
        }

        /**
         * @brief Initializes a new Loop instance from an existing resource.
         *
         * The lifetime of the resource must exceed that of the instance to which
         * it's associated. Management of the memory associated with the resource is
         * in charge of the user.
         *
         * @param loop A valid pointer to a correctly initialized resource.
         * @return A pointer to the newly created loop.
         */
        static std::shared_ptr<Loop> create(uv_loop_t *loop)
        {
            auto ptr = std::unique_ptr<uv_loop_t, Deleter>{ loop, [](uv_loop_t *) {
                                                           } };
            return std::shared_ptr<Loop>{ new Loop{ std::move(ptr) } };
        }

        /**
         * @brief Gets the initialized default loop.
         *
         * It may return an empty pointer in case of failure.<br>
         * This function is just a convenient way for having a global loop
         * throughout an application, the default loop is in no way different than
         * the ones initialized with `create()`.<br>
         * As such, the default loop can be closed with `close()` so the resources
         * associated with it are freed (even if it is not strictly necessary).
         *
         * @return The initialized default loop.
         */
        static std::shared_ptr<Loop> getDefault()
        {
            static std::weak_ptr<Loop> ref;
            std::shared_ptr<Loop> loop;

            if (ref.expired())
            {
                auto def = uv_default_loop();

                if (def)
                {
                    auto ptr = std::unique_ptr<uv_loop_t, Deleter>(def, [](uv_loop_t *) {});
                    loop = std::shared_ptr<Loop>{ new Loop{ std::move(ptr) } };
                }

                ref = loop;
            }
            else
            {
                loop = ref.lock();
            }

            return loop;
        }

        Loop(const Loop &) = delete;
        Loop(Loop &&other) = delete;
        Loop &operator=(const Loop &) = delete;
        Loop &operator=(Loop &&other) = delete;

        ~Loop() noexcept
        {
            if (loop)
            {
                close();
            }
        }

        /**
         * @brief Sets additional loop options.
         *
         * You should normally call this before the first call to uv_run() unless
         * mentioned otherwise.<br/>
         * Supported options:
         *
         * * `Loop::Configure::BLOCK_SIGNAL`: Block a signal when polling for new
         * events. A second argument is required and it is the signal number.
         *
         * An ErrorEvent will be emitted in case of errors.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/loop.html#c.uv_loop_configure)
         * for further details.
         */
        template<typename... Args>
        void configure(Configure flag, Args &&... args)
        {
            auto option = static_cast<std::underlying_type_t<Configure>>(flag);
            auto err = uv_loop_configure(loop.get(), static_cast<uv_loop_option>(option), std::forward<Args>(args)...);
            if (err)
            {
                publish(ErrorEvent{ err });
            }
        }

        /**
         * @brief Creates resources of any type.
         *
         * This should be used as a default method to create resources.<br/>
         * The arguments are the ones required for the specific resource.
         *
         * Use it as `loop->resource<uvw::TimerHandle>()`.
         *
         * @return A pointer to the newly created resource.
         */
        template<typename R, typename... Args>
        std::shared_ptr<R> resource(Args &&... args)
        {
            if constexpr (std::is_base_of_v<BaseHandle, R>)
            {
                auto ptr = R::create(shared_from_this(), std::forward<Args>(args)...);
                ptr = ptr->init() ? ptr : nullptr;
                return ptr;
            }
            else
            {
                return R::create(shared_from_this(), std::forward<Args>(args)...);
            }
        }

        /**
         * @brief Releases all internal loop resources.
         *
         * Call this function only when the loop has finished executing and all open
         * handles and requests have been closed, or the loop will emit an error.
         *
         * An ErrorEvent will be emitted in case of errors.
         */
        void close()
        {
            auto err = uv_loop_close(loop.get());
            return err ? publish(ErrorEvent{ err }) : loop.reset();
        }

        /**
         * @brief Runs the event loop.
         *
         * Available modes are:
         *
         * * `Loop::Mode::DEFAULT`: Runs the event loop until there are no more
         * active and referenced handles or requests.
         * * `Loop::Mode::ONCE`: Poll for i/o once. Note that this function blocks
         * if there are no pending callbacks.
         * * `Loop::Mode::NOWAIT`: Poll for i/o once but don’t block if there are no
         * pending callbacks.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/loop.html#c.uv_run)
         * for further details.
         *
         * @return True when done, false in all other cases.
         */
        template<Mode mode = Mode::DEFAULT>
        bool run() noexcept
        {
            auto utm = static_cast<std::underlying_type_t<Mode>>(mode);
            auto uvrm = static_cast<uv_run_mode>(utm);
            return (uv_run(loop.get(), uvrm) == 0);
        }

        /**
         * @brief Checks if there are active resources.
         * @return True if there are active resources in the loop.
         */
        bool alive() const noexcept
        {
            return !(uv_loop_alive(loop.get()) == 0);
        }

        /**
         * @brief Stops the event loop.
         *
         * It causes `run()` to end as soon as possible.<br/>
         * This will happen not sooner than the next loop iteration.<br/>
         * If this function was called before blocking for I/O, the loop won’t block
         * for I/O on this iteration.
         */
        void stop() noexcept
        {
            uv_stop(loop.get());
        }

        /**
         * @brief Get backend file descriptor.
         *
         * Only kqueue, epoll and event ports are supported.<br/>
         * This can be used in conjunction with `run<Loop::Mode::NOWAIT>()` to poll
         * in one thread and run the event loop’s callbacks in another.
         *
         * @return The backend file descriptor.
         */
        int descriptor() const noexcept
        {
            return uv_backend_fd(loop.get());
        }

        /**
         * @brief Gets the poll timeout.
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of valid timeout, false otherwise.
         * * Milliseconds (`std::chrono::duration<uint64_t, std::milli>`).
         */
        std::pair<bool, Time> timeout() const noexcept
        {
            auto to = uv_backend_timeout(loop.get());
            return std::make_pair(to == -1, Time{ to });
        }

        /**
         * @brief Returns the current timestamp in milliseconds.
         *
         * The timestamp is cached at the start of the event loop tick.<br/>
         * The timestamp increases monotonically from some arbitrary point in
         * time.<br/>
         * Don’t make assumptions about the starting point, you will only get
         * disappointed.
         *
         * @return The current timestamp in milliseconds (actual type is
         * `std::chrono::duration<uint64_t, std::milli>`).
         */
        Time now() const noexcept
        {
            return Time{ uv_now(loop.get()) };
        }

        /**
         * @brief Updates the event loop’s concept of _now_.
         *
         * The current time is cached at the start of the event loop tick in order
         * to reduce the number of time-related system calls.<br/>
         * You won’t normally need to call this function unless you have callbacks
         * that block the event loop for longer periods of time, where _longer_ is
         * somewhat subjective but probably on the order of a millisecond or more.
         */
        void update() const noexcept
        {
            return uv_update_time(loop.get());
        }

        /**
         * @brief Walks the list of handles.
         *
         * The callback will be executed once for each handle that is still active.
         *
         * @param callback A function to be invoked once for each active handle.
         */
        void walk(std::function<void(BaseHandle &)> callback)
        {
            // remember: non-capturing lambdas decay to pointers to functions
            uv_walk(
                loop.get(),
                [](uv_handle_t *handle, void *func) {
                    BaseHandle &ref = *static_cast<BaseHandle *>(handle->data);
                    std::function<void(BaseHandle &)> &f = *static_cast<std::function<void(BaseHandle &)> *>(func);
                    f(ref);
                },
                &callback);
        }

        /**
         * @brief Reinitialize any kernel state necessary in the child process after
         * a fork(2) system call.
         *
         * Previously started watchers will continue to be started in the child
         * process.
         *
         * It is necessary to explicitly call this function on every event loop
         * created in the parent process that you plan to continue to use in the
         * child, including the default loop (even if you don’t continue to use it
         * in the parent). This function must be called before calling any API
         * function using the loop in the child. Failure to do so will result in
         * undefined behaviour, possibly including duplicate events delivered to
         * both parent and child or aborting the child process.
         *
         * When possible, it is preferred to create a new loop in the child process
         * instead of reusing a loop created in the parent. New loops created in the
         * child process after the fork should not use this function.
         *
         * Note that this function is not implemented on Windows.<br/>
         * Note also that this function is experimental in `libuv`. It may contain
         * bugs, and is subject to change or removal. API and ABI stability is not
         * guaranteed.
         *
         * An ErrorEvent will be emitted in case of errors.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/loop.html#c.uv_loop_fork)
         * for further details.
         */
        void fork() noexcept
        {
            auto err = uv_loop_fork(loop.get());
            if (err)
            {
                publish(ErrorEvent{ err });
            }
        }

        /**
         * @brief Gets user-defined data. `uvw` won't use this field in any case.
         * @return User-defined data if any, an invalid pointer otherwise.
         */
        template<typename R = void>
        std::shared_ptr<R> data() const
        {
            return std::static_pointer_cast<R>(userData);
        }

        /**
         * @brief Sets arbitrary data. `uvw` won't use this field in any case.
         * @param uData User-defined arbitrary data.
         */
        void data(std::shared_ptr<void> uData)
        {
            userData = std::move(uData);
        }

        /**
         * @brief Gets the underlying raw data structure.
         *
         * This function should not be used, unless you know exactly what you are
         * doing and what are the risks.<br/>
         * Going raw is dangerous, mainly because the lifetime management of a loop,
         * a handle or a request is in charge to the library itself and users should
         * not work around it.
         *
         * @warning
         * Use this function at your own risk, but do not expect any support in case
         * of bugs.
         *
         * @return The underlying raw data structure.
         */
        const uv_loop_t *raw() const noexcept
        {
            return loop.get();
        }

        /**
         * @brief Gets the underlying raw data structure.
         *
         * This function should not be used, unless you know exactly what you are
         * doing and what are the risks.<br/>
         * Going raw is dangerous, mainly because the lifetime management of a loop,
         * a handle or a request is in charge to the library itself and users should
         * not work around it.
         *
         * @warning
         * Use this function at your own risk, but do not expect any support in case
         * of bugs.
         *
         * @return The underlying raw data structure.
         */
        uv_loop_t *raw() noexcept
        {
            return const_cast<uv_loop_t *>(const_cast<const Loop *>(this)->raw());
        }

      private:
        std::unique_ptr<uv_loop_t, Deleter> loop;
        std::shared_ptr<void> userData{ nullptr };
    };

} // namespace uvw

/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief Wrapper class for underlying types.
     *
     * It acts mainly as a wrapper around data structures of the underlying library.
     */
    template<typename T, typename U>
    class UnderlyingType
    {
        template<typename, typename>
        friend class UnderlyingType;

      protected:
        struct ConstructorAccess
        {
            explicit ConstructorAccess(int)
            {
            }
        };

        template<typename R = U>
        auto get() noexcept
        {
            return reinterpret_cast<R *>(&resource);
        }

        template<typename R = U>
        auto get() const noexcept
        {
            return reinterpret_cast<const R *>(&resource);
        }

        template<typename R, typename... P>
        auto get(UnderlyingType<P...> &other) noexcept
        {
            return reinterpret_cast<R *>(&other.resource);
        }

      public:
        explicit UnderlyingType(ConstructorAccess, std::shared_ptr<Loop> ref) noexcept : pLoop{ std::move(ref) }, resource{}
        {
        }

        UnderlyingType(const UnderlyingType &) = delete;
        UnderlyingType(UnderlyingType &&) = delete;

        virtual ~UnderlyingType()
        {
            static_assert(std::is_base_of_v<UnderlyingType<T, U>, T>);
        }

        UnderlyingType &operator=(const UnderlyingType &) = delete;
        UnderlyingType &operator=(UnderlyingType &&) = delete;

        /**
         * @brief Creates a new resource of the given type.
         * @param args Arguments to be forwarded to the actual constructor (if any).
         * @return A pointer to the newly created resource.
         */
        template<typename... Args>
        static std::shared_ptr<T> create(Args &&... args)
        {
            return std::make_shared<T>(ConstructorAccess{ 0 }, std::forward<Args>(args)...);
        }

        /**
         * @brief Gets the loop from which the resource was originated.
         * @return A reference to a loop instance.
         */
        Loop &loop() const noexcept
        {
            return *pLoop;
        }

        /**
         * @brief Gets the underlying raw data structure.
         *
         * This function should not be used, unless you know exactly what you are
         * doing and what are the risks.<br/>
         * Going raw is dangerous, mainly because the lifetime management of a loop,
         * a handle or a request is in charge to the library itself and users should
         * not work around it.
         *
         * @warning
         * Use this function at your own risk, but do not expect any support in case
         * of bugs.
         *
         * @return The underlying raw data structure.
         */
        const U *raw() const noexcept
        {
            return &resource;
        }

        /**
         * @brief Gets the underlying raw data structure.
         *
         * This function should not be used, unless you know exactly what you are
         * doing and what are the risks.<br/>
         * Going raw is dangerous, mainly because the lifetime management of a loop,
         * a handle or a request is in charge to the library itself and users should
         * not work around it.
         *
         * @warning
         * Use this function at your own risk, but do not expect any support in case
         * of bugs.
         *
         * @return The underlying raw data structure.
         */
        U *raw() noexcept
        {
            return const_cast<U *>(const_cast<const UnderlyingType *>(this)->raw());
        }

      private:
        std::shared_ptr<Loop> pLoop;
        U resource;
    };

} // namespace uvw

/*-- #include "uvw/underlying_type.hpp" end --*/

namespace uvw
{

    /**
     * @brief Common class for almost all the resources available in `uvw`.
     *
     * This is the base class for handles and requests.
     */
    template<typename T, typename U>
    class Resource
        : public UnderlyingType<T, U>
        , public Emitter<T>
        , public std::enable_shared_from_this<T>
    {
      protected:
        using ConstructorAccess = typename UnderlyingType<T, U>::ConstructorAccess;

        auto parent() const noexcept
        {
            return this->loop().loop.get();
        }

        void leak() noexcept
        {
            sPtr = this->shared_from_this();
        }

        void reset() noexcept
        {
            sPtr.reset();
        }

        bool self() const noexcept
        {
            return static_cast<bool>(sPtr);
        }

      public:
        explicit Resource(ConstructorAccess ca, std::shared_ptr<Loop> ref)
            : UnderlyingType<T, U>{ ca, std::move(ref) }, Emitter<T>{}, std::enable_shared_from_this<T>{}
        {
            this->get()->data = static_cast<T *>(this);
        }

        /**
         * @brief Gets user-defined data. `uvw` won't use this field in any case.
         * @return User-defined data if any, an invalid pointer otherwise.
         */
        template<typename R = void>
        std::shared_ptr<R> data() const
        {
            return std::static_pointer_cast<R>(userData);
        }

        /**
         * @brief Sets arbitrary data. `uvw` won't use this field in any case.
         * @param uData User-defined arbitrary data.
         */
        void data(std::shared_ptr<void> uData)
        {
            userData = std::move(uData);
        }

      private:
        std::shared_ptr<void> userData{ nullptr };
        std::shared_ptr<void> sPtr{ nullptr };
    };

} // namespace uvw

/*-- #include "uvw/resource.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    /**
     * @brief CloseEvent event.
     *
     * It will be emitted by the handles according with their functionalities.
     */
    struct CloseEvent
    {
    };

    /**
     * @brief Handle base class.
     *
     * Base type for all `uvw` handle types.
     */
    template<typename T, typename U>
    class Handle
        : public BaseHandle
        , public Resource<T, U>
    {
      protected:
        static void closeCallback(uv_handle_t *handle)
        {
            Handle<T, U> &ref = *(static_cast<T *>(handle->data));
            auto ptr = ref.shared_from_this();
            (void) ptr;
            ref.reset();
            ref.publish(CloseEvent{});
        }

        static void allocCallback(uv_handle_t *, std::size_t suggested, uv_buf_t *buf)
        {
            auto size = static_cast<unsigned int>(suggested);
            *buf = uv_buf_init(new char[size], size);
        }

        template<typename F, typename... Args>
        bool initialize(F &&f, Args &&... args)
        {
            if (!this->self())
            {
                auto err = std::forward<F>(f)(this->parent(), this->get(), std::forward<Args>(args)...);

                if (err)
                {
                    this->publish(ErrorEvent{ err });
                }
                else
                {
                    this->leak();
                }
            }

            return this->self();
        }

        template<typename F, typename... Args>
        void invoke(F &&f, Args &&... args)
        {
            auto err = std::forward<F>(f)(std::forward<Args>(args)...);
            if (err)
            {
                Emitter<T>::publish(ErrorEvent{ err });
            }
        }

      public:
        using Resource<T, U>::Resource;

        /**
         * @brief Gets the category of the handle.
         *
         * A base handle offers no functionality to promote it to the actual handle
         * type. By means of this function, an opaque value that identifies the
         * category of the handle is made available to the users.
         *
         * @return The actual category of the handle.
         */
        HandleCategory category() const noexcept override
        {
            return HandleCategory{ this->template get<uv_handle_t>()->type };
        }

        /**
         * @brief Gets the type of the handle.
         *
         * A base handle offers no functionality to promote it to the actual handle
         * type. By means of this function, the type of the underlying handle as
         * specified by HandleType is made available to the users.
         *
         * @return The actual type of the handle.
         */
        HandleType type() const noexcept override
        {
            return Utilities::guessHandle(category());
        }

        /**
         * @brief Checks if the handle is active.
         *
         * What _active_ means depends on the type of handle:
         *
         * * An AsyncHandle handle is always active and cannot be deactivated,
         * except by closing it with uv_close().
         * * A PipeHandle, TCPHandle, UDPHandle, etc. handle - basically any handle
         * that deals with I/O - is active when it is doing something that involves
         * I/O, like reading, writing, connecting, accepting new connections, etc.
         * * A CheckHandle, IdleHandle, TimerHandle, etc. handle is active when it
         * has been started with a call to `start()`.
         *
         * Rule of thumb: if a handle of type `FooHandle` has a `start()` member
         * method, then it’s active from the moment that method is called. Likewise,
         * `stop()` deactivates the handle again.
         *
         * @return True if the handle is active, false otherwise.
         */
        bool active() const noexcept override
        {
            return !(uv_is_active(this->template get<uv_handle_t>()) == 0);
        }

        /**
         * @brief Checks if a handle is closing or closed.
         *
         * This function should only be used between the initialization of the
         * handle and the arrival of the close callback.
         *
         * @return True if the handle is closing or closed, false otherwise.
         */
        bool closing() const noexcept override
        {
            return !(uv_is_closing(this->template get<uv_handle_t>()) == 0);
        }

        /**
         * @brief Request handle to be closed.
         *
         * This **must** be called on each handle before memory is released.<br/>
         * In-progress requests are cancelled and this can result in an ErrorEvent
         * emitted.
         *
         * The handle will emit a CloseEvent when finished.
         */
        void close() noexcept override
        {
            if (!closing())
            {
                uv_close(this->template get<uv_handle_t>(), &Handle<T, U>::closeCallback);
            }
        }

        /**
         * @brief Reference the given handle.
         *
         * References are idempotent, that is, if a handle is already referenced
         * calling this function again will have no effect.
         */
        void reference() noexcept override
        {
            uv_ref(this->template get<uv_handle_t>());
        }

        /**
         * @brief Unreference the given handle.
         *
         * References are idempotent, that is, if a handle is not referenced calling
         * this function again will have no effect.
         */
        void unreference() noexcept override
        {
            uv_unref(this->template get<uv_handle_t>());
        }

        /**
         * @brief Checks if the given handle referenced.
         * @return True if the handle referenced, false otherwise.
         */
        bool referenced() const noexcept override
        {
            return !(uv_has_ref(this->template get<uv_handle_t>()) == 0);
        }

        /**
         * @brief Returns the size of the underlying handle type.
         * @return The size of the underlying handle type.
         */
        std::size_t size() const noexcept
        {
            return uv_handle_size(this->template get<uv_handle_t>()->type);
        }

        /**
         * @brief Gets the size of the send buffer used for the socket.
         *
         * Gets the size of the send buffer that the operating system uses for the
         * socket.<br/>
         * This function works for TCPHandle, PipeHandle and UDPHandle handles on
         * Unix and for TCPHandle and UDPHandle handles on Windows.<br/>
         * Note that Linux will return double the size of the original set value.
         *
         * @return The size of the send buffer, 0 in case of errors.
         */
        int sendBufferSize()
        {
            int value = 0;
            auto err = uv_send_buffer_size(this->template get<uv_handle_t>(), &value);
            return err ? 0 : value;
        }

        /**
         * @brief Sets the size of the send buffer used for the socket.
         *
         * Sets the size of the send buffer that the operating system uses for the
         * socket.<br/>
         * This function works for TCPHandle, PipeHandle and UDPHandle handles on
         * Unix and for TCPHandle and UDPHandle handles on Windows.<br/>
         * Note that Linux will set double the size.
         *
         * @return True in case of success, false otherwise.
         */
        bool sendBufferSize(int value)
        {
            return (0 == uv_send_buffer_size(this->template get<uv_handle_t>(), &value));
        }

        /**
         * @brief Gets the size of the receive buffer used for the socket.
         *
         * Gets the size of the receive buffer that the operating system uses for
         * the socket.<br/>
         * This function works for TCPHandle, PipeHandle and UDPHandle handles on
         * Unix and for TCPHandle and UDPHandle handles on Windows.<br/>
         * Note that Linux will return double the size of the original set value.
         *
         * @return The size of the receive buffer, 0 in case of errors.
         */
        int recvBufferSize()
        {
            int value = 0;
            auto err = uv_recv_buffer_size(this->template get<uv_handle_t>(), &value);
            return err ? 0 : value;
        }

        /**
         * @brief Sets the size of the receive buffer used for the socket.
         *
         * Sets the size of the receive buffer that the operating system uses for
         * the socket.<br/>
         * This function works for TCPHandle, PipeHandle and UDPHandle handles on
         * Unix and for TCPHandle and UDPHandle handles on Windows.<br/>
         * Note that Linux will set double the size.
         *
         * @return True in case of success, false otherwise.
         */
        bool recvBufferSize(int value)
        {
            return (0 == uv_recv_buffer_size(this->template get<uv_handle_t>(), &value));
        }

        /**
         * @brief Gets the platform dependent file descriptor equivalent.
         *
         * Supported handles:
         *
         * * TCPHandle
         * * PipeHandle
         * * TTYHandle
         * * UDPHandle
         * * PollHandle
         *
         * It will emit an ErrorEvent event if invoked on any other handle.<br/>
         * If a handle doesn’t have an attached file descriptor yet or the handle
         * itself has been closed, an ErrorEvent event will be emitted.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/handle.html#c.uv_fileno)
         * for further details.
         *
         * @return The file descriptor attached to the hande or a negative value in
         * case of errors.
         */
        OSFileDescriptor fileno() const
        {
            uv_os_fd_t fd;
            uv_fileno(this->template get<uv_handle_t>(), &fd);
            return fd;
        }
    };

} // namespace uvw

/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief AsyncEvent event.
     *
     * It will be emitted by AsyncHandle according with its functionalities.
     */
    struct AsyncEvent
    {
    };

    /**
     * @brief The AsyncHandle handle.
     *
     * Async handles allow the user to _wakeup_ the event loop and get an event
     * emitted from another thread.
     *
     * To create an `AsyncHandle` through a `Loop`, no arguments are required.
     */
    class AsyncHandle final : public Handle<AsyncHandle, uv_async_t>
    {
        static void sendCallback(uv_async_t *handle)
        {
            AsyncHandle &async = *(static_cast<AsyncHandle *>(handle->data));
            async.publish(AsyncEvent{});
        }

      public:
        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         *
         * Unlike other handle initialization functions, it immediately starts the
         * handle.
         *
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_async_init, &sendCallback);
        }

        /**
         * @brief Wakeups the event loop and emits the AsyncEvent event.
         *
         * It’s safe to call this function from any thread.<br/>
         * An AsyncEvent event will be emitted on the loop thread.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/async.html#c.uv_async_send)
         * for further details.
         */
        void send()
        {
            invoke(&uv_async_send, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/async.hpp" end --*/
/*-- #include "uvw/check.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief CheckEvent event.
     *
     * It will be emitted by CheckHandle according with its functionalities.
     */
    struct CheckEvent
    {
    };

    /**
     * @brief The CheckHandle handle.
     *
     * Check handles will emit a CheckEvent event once per loop iteration, right
     * after polling for I/O.
     *
     * To create a `CheckHandle` through a `Loop`, no arguments are required.
     */
    class CheckHandle final : public Handle<CheckHandle, uv_check_t>
    {
        static void startCallback(uv_check_t *handle)
        {
            CheckHandle &check = *(static_cast<CheckHandle *>(handle->data));
            check.publish(CheckEvent{});
        }

      public:
        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_check_init);
        }

        /**
         * @brief Starts the handle.
         *
         * A CheckEvent event will be emitted once per loop iteration, right after
         * polling for I/O.
         */
        void start()
        {
            invoke(&uv_check_start, get(), &startCallback);
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_check_stop, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/check.hpp" end --*/
/*-- #include "uvw/dns.hpp" start --*/

#include <memory>
#include <string>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/

#include <memory>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/resource.hpp" start --*/
/*-- #include "uvw/resource.hpp" end --*/

namespace uvw
{

    template<typename T, typename U>
    class Request : public Resource<T, U>
    {
      protected:
        static auto reserve(U *req)
        {
            auto ptr = static_cast<T *>(req->data)->shared_from_this();
            ptr->reset();
            return ptr;
        }

        template<typename E>
        static void defaultCallback(U *req, int status)
        {
            auto ptr = reserve(req);
            if (status)
            {
                ptr->publish(ErrorEvent{ status });
            }
            else
            {
                ptr->publish(E{});
            }
        }

        template<typename F, typename... Args>
        auto invoke(F &&f, Args &&... args)
        {
            if constexpr (std::is_void_v<std::invoke_result_t<F, Args...>>)
            {
                std::forward<F>(f)(std::forward<Args>(args)...);
                this->leak();
            }
            else
            {
                auto err = std::forward<F>(f)(std::forward<Args>(args)...);
                if (err)
                {
                    Emitter<T>::publish(ErrorEvent{ err });
                }
                else
                {
                    this->leak();
                }
            }
        }

      public:
        using Resource<T, U>::Resource;

        /**
         * @brief Cancels a pending request.
         *
         * This method fails if the request is executing or has finished
         * executing.<br/>
         * It can emit an ErrorEvent event in case of errors.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/request.html#c.uv_cancel)
         * for further details.
         *
         * @return True in case of success, false otherwise.
         */
        bool cancel()
        {
            return (0 == uv_cancel(this->template get<uv_req_t>()));
        }

        /**
         * @brief Returns the size of the underlying request type.
         * @return The size of the underlying request type.
         */
        std::size_t size() const noexcept
        {
            return uv_req_size(this->template get<uv_req_t>()->type);
        }
    };

} // namespace uvw

/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief AddrInfoEvent event.
     *
     * It will be emitted by GetAddrInfoReq according with its functionalities.
     */
    struct AddrInfoEvent
    {
        using Deleter = void (*)(addrinfo *);

        AddrInfoEvent(std::unique_ptr<addrinfo, Deleter> addr) : data{ std::move(addr) }
        {
        }

        /**
         * @brief An initialized instance of `addrinfo`.
         *
         * See [getaddrinfo](http://linux.die.net/man/3/getaddrinfo) for further
         * details.
         */
        std::unique_ptr<addrinfo, Deleter> data;
    };

    /**
     * @brief NameInfoEvent event.
     *
     * It will be emitted by GetNameInfoReq according with its functionalities.
     */
    struct NameInfoEvent
    {
        NameInfoEvent(const char *host, const char *serv) : hostname{ host }, service{ serv }
        {
        }

        /**
         * @brief A valid hostname.
         *
         * See [getnameinfo](http://linux.die.net/man/3/getnameinfo) for further
         * details.
         */
        const char *hostname;

        /**
         * @brief A valid service name.
         *
         * See [getnameinfo](http://linux.die.net/man/3/getnameinfo) for further
         * details.
         */
        const char *service;
    };

    /**
     * @brief The GetAddrInfoReq request.
     *
     * Wrapper for [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).<br/>
     * It offers either asynchronous and synchronous access methods.
     *
     * To create a `GetAddrInfoReq` through a `Loop`, no arguments are required.
     */
    class GetAddrInfoReq final : public Request<GetAddrInfoReq, uv_getaddrinfo_t>
    {
        static void addrInfoCallback(uv_getaddrinfo_t *req, int status, addrinfo *res)
        {
            auto ptr = reserve(req);

            if (status)
            {
                ptr->publish(ErrorEvent{ status });
            }
            else
            {
                auto data = std::unique_ptr<addrinfo, void (*)(addrinfo *)>{ res, [](addrinfo *addr) {
                                                                                uv_freeaddrinfo(addr);
                                                                            } };

                ptr->publish(AddrInfoEvent{ std::move(data) });
            }
        }

        void nodeAddrInfo(const char *node, const char *service, addrinfo *hints = nullptr)
        {
            invoke(&uv_getaddrinfo, parent(), get(), &addrInfoCallback, node, service, hints);
        }

        auto nodeAddrInfoSync(const char *node, const char *service, addrinfo *hints = nullptr)
        {
            auto req = get();
            auto err = uv_getaddrinfo(parent(), req, nullptr, node, service, hints);
            auto data = std::unique_ptr<addrinfo, void (*)(addrinfo *)>{ req->addrinfo, [](addrinfo *addr) {
                                                                            uv_freeaddrinfo(addr);
                                                                        } };
            return std::make_pair(!err, std::move(data));
        }

      public:
        using Deleter = void (*)(addrinfo *);

        using Request::Request;

        /**
         * @brief Async [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         * @param node Either a numerical network address or a network hostname.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         */
        void nodeAddrInfo(std::string node, addrinfo *hints = nullptr)
        {
            nodeAddrInfo(node.data(), nullptr, hints);
        }

        /**
         * @brief Sync [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         *
         * @param node Either a numerical network address or a network hostname.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::unique_ptr<addrinfo, Deleter>` containing the data requested.
         */
        std::pair<bool, std::unique_ptr<addrinfo, Deleter>> nodeAddrInfoSync(std::string node, addrinfo *hints = nullptr)
        {
            return nodeAddrInfoSync(node.data(), nullptr, hints);
        }

        /**
         * @brief Async [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         * @param service Either a service name or a port number as a string.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         */
        void serviceAddrInfo(std::string service, addrinfo *hints = nullptr)
        {
            nodeAddrInfo(nullptr, service.data(), hints);
        }

        /**
         * @brief Sync [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         *
         * @param service Either a service name or a port number as a string.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::unique_ptr<addrinfo, Deleter>` containing the data requested.
         */
        std::pair<bool, std::unique_ptr<addrinfo, Deleter>> serviceAddrInfoSync(std::string service, addrinfo *hints = nullptr)
        {
            return nodeAddrInfoSync(nullptr, service.data(), hints);
        }

        /**
         * @brief Async [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         * @param node Either a numerical network address or a network hostname.
         * @param service Either a service name or a port number as a string.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         */
        void addrInfo(std::string node, std::string service, addrinfo *hints = nullptr)
        {
            nodeAddrInfo(node.data(), service.data(), hints);
        }

        /**
         * @brief Sync [getaddrinfo](http://linux.die.net/man/3/getaddrinfo).
         *
         * @param node Either a numerical network address or a network hostname.
         * @param service Either a service name or a port number as a string.
         * @param hints Optional `addrinfo` data structure with additional address
         * type constraints.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::unique_ptr<addrinfo, Deleter>` containing the data requested.
         */
        std::pair<bool, std::unique_ptr<addrinfo, Deleter>> addrInfoSync(std::string node, std::string service, addrinfo *hints = nullptr)
        {
            return nodeAddrInfoSync(node.data(), service.empty()? nullptr : service.data(), hints);
        }
    };

    /**
     * @brief The GetNameInfoReq request.
     *
     * Wrapper for [getnameinfo](http://linux.die.net/man/3/getnameinfo).<br/>
     * It offers either asynchronous and synchronous access methods.
     *
     * To create a `GetNameInfoReq` through a `Loop`, no arguments are required.
     */
    class GetNameInfoReq final : public Request<GetNameInfoReq, uv_getnameinfo_t>
    {
        static void nameInfoCallback(uv_getnameinfo_t *req, int status, const char *hostname, const char *service)
        {
            auto ptr = reserve(req);
            if (status)
            {
                ptr->publish(ErrorEvent{ status });
            }
            else
            {
                ptr->publish(NameInfoEvent{ hostname, service });
            }
        }

      public:
        using Request::Request;

        /**
         * @brief Async [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         */
        void nameInfo(const sockaddr &addr, int flags = 0)
        {
            invoke(&uv_getnameinfo, parent(), get(), &nameInfoCallback, &addr, flags);
        }

        /**
         * @brief Async [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         * @param ip A valid IP address.
         * @param port A valid port number.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         */
        template<typename I = IPv4>
        void nameInfo(std::string ip, unsigned int port, int flags = 0)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            nameInfo(reinterpret_cast<const sockaddr &>(addr), flags);
        }

        /**
         * @brief Async [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         * @param addr A valid instance of Addr.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         */
        template<typename I = IPv4>
        void nameInfo(Addr addr, int flags = 0)
        {
            nameInfo<I>(std::move(addr.ip), addr.port, flags);
        }

        /**
         * @brief Sync [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::pair` composed as it follows:
         *   * A `const char *` containing a valid hostname.
         *   * A `const char *` containing a valid service name.
         */
        std::pair<bool, std::pair<const char *, const char *>> nameInfoSync(const sockaddr &addr, int flags = 0)
        {
            auto req = get();
            auto err = uv_getnameinfo(parent(), req, nullptr, &addr, flags);
            return std::make_pair(!err, std::make_pair(req->host, req->service));
        }

        /**
         * @brief Sync [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         *
         * @param ip A valid IP address.
         * @param port A valid port number.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::pair` composed as it follows:
         *   * A `const char *` containing a valid hostname.
         *   * A `const char *` containing a valid service name.
         */
        template<typename I = IPv4>
        std::pair<bool, std::pair<const char *, const char *>> nameInfoSync(std::string ip, unsigned int port, int flags = 0)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            return nameInfoSync(reinterpret_cast<const sockaddr &>(addr), flags);
        }

        /**
         * @brief Sync [getnameinfo](http://linux.die.net/man/3/getnameinfo).
         *
         * @param addr A valid instance of Addr.
         * @param flags Optional flags that modify the behavior of `getnameinfo`.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::pair` composed as it follows:
         *   * A `const char *` containing a valid hostname.
         *   * A `const char *` containing a valid service name.
         */
        template<typename I = IPv4>
        std::pair<bool, std::pair<const char *, const char *>> nameInfoSync(Addr addr, int flags = 0)
        {
            return nameInfoSync<I>(std::move(addr.ip), addr.port, flags);
        }
    };

} // namespace uvw

/*-- #include "uvw/dns.hpp" end --*/
/*-- #include "uvw/fs.hpp" start --*/

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVFsType : std::underlying_type_t<uv_fs_type>
        {
            UNKNOWN = UV_FS_UNKNOWN,
            CUSTOM = UV_FS_CUSTOM,
            OPEN = UV_FS_OPEN,
            CLOSE = UV_FS_CLOSE,
            READ = UV_FS_READ,
            WRITE = UV_FS_WRITE,
            SENDFILE = UV_FS_SENDFILE,
            STAT = UV_FS_STAT,
            LSTAT = UV_FS_LSTAT,
            FSTAT = UV_FS_FSTAT,
            FTRUNCATE = UV_FS_FTRUNCATE,
            UTIME = UV_FS_UTIME,
            FUTIME = UV_FS_FUTIME,
            ACCESS = UV_FS_ACCESS,
            CHMOD = UV_FS_CHMOD,
            FCHMOD = UV_FS_FCHMOD,
            FSYNC = UV_FS_FSYNC,
            FDATASYNC = UV_FS_FDATASYNC,
            UNLINK = UV_FS_UNLINK,
            RMDIR = UV_FS_RMDIR,
            MKDIR = UV_FS_MKDIR,
            MKDTEMP = UV_FS_MKDTEMP,
            RENAME = UV_FS_RENAME,
            SCANDIR = UV_FS_SCANDIR,
            LINK = UV_FS_LINK,
            SYMLINK = UV_FS_SYMLINK,
            READLINK = UV_FS_READLINK,
            CHOWN = UV_FS_CHOWN,
            FCHOWN = UV_FS_FCHOWN,
            REALPATH = UV_FS_REALPATH,
            COPYFILE = UV_FS_COPYFILE,
            LCHOWN = UV_FS_LCHOWN,
            OPENDIR = UV_FS_OPENDIR,
            READDIR = UV_FS_READDIR,
            CLOSEDIR = UV_FS_CLOSEDIR,
            STATFS = UV_FS_STATFS,
            MKSTEMP = UV_FS_MKSTEMP
        };

        enum class UVDirentTypeT : std::underlying_type_t<uv_dirent_type_t>
        {
            UNKNOWN = UV_DIRENT_UNKNOWN,
            FILE = UV_DIRENT_FILE,
            DIR = UV_DIRENT_DIR,
            LINK = UV_DIRENT_LINK,
            FIFO = UV_DIRENT_FIFO,
            SOCKET = UV_DIRENT_SOCKET,
            CHAR = UV_DIRENT_CHAR,
            BLOCK = UV_DIRENT_BLOCK
        };

        enum class UVFileOpenFlags : int
        {
            APPEND = UV_FS_O_APPEND,
            CREAT = UV_FS_O_CREAT,
            DIRECT = UV_FS_O_DIRECT,
            DIRECTORY = UV_FS_O_DIRECTORY,
            DSYNC = UV_FS_O_DSYNC,
            EXCL = UV_FS_O_EXCL,
            EXLOCK = UV_FS_O_EXLOCK,
            FILEMAP = UV_FS_O_FILEMAP,
            NOATIME = UV_FS_O_NOATIME,
            NOCTTY = UV_FS_O_NOCTTY,
            NOFOLLOW = UV_FS_O_NOFOLLOW,
            NONBLOCK = UV_FS_O_NONBLOCK,
            RANDOM = UV_FS_O_RANDOM,
            RDONLY = UV_FS_O_RDONLY,
            RDWR = UV_FS_O_RDWR,
            SEQUENTIAL = UV_FS_O_SEQUENTIAL,
            SHORT_LIVED = UV_FS_O_SHORT_LIVED,
            SYMLINK = UV_FS_O_SYMLINK,
            SYNC = UV_FS_O_SYNC,
            TEMPORARY = UV_FS_O_TEMPORARY,
            TRUNC = UV_FS_O_TRUNC,
            WRONLY = UV_FS_O_WRONLY
        };

        enum class UVCopyFileFlags : int
        {
            EXCL = UV_FS_COPYFILE_EXCL,
            FICLONE = UV_FS_COPYFILE_FICLONE,
            FICLONE_FORCE = UV_FS_COPYFILE_FICLONE_FORCE
        };

        enum class UVSymLinkFlags : int
        {
            DIR = UV_FS_SYMLINK_DIR,
            JUNCTION = UV_FS_SYMLINK_JUNCTION
        };

    } // namespace details

    /**
     * @brief Default FsEvent event.
     *
     * Available types are:
     *
     * * `FsRequest::Type::UNKNOWN`
     * * `FsRequest::Type::CUSTOM`
     * * `FsRequest::Type::OPEN`
     * * `FsRequest::Type::CLOSE`
     * * `FsRequest::Type::READ`
     * * `FsRequest::Type::WRITE`
     * * `FsRequest::Type::SENDFILE`
     * * `FsRequest::Type::STAT`
     * * `FsRequest::Type::LSTAT`
     * * `FsRequest::Type::FSTAT`
     * * `FsRequest::Type::FTRUNCATE`
     * * `FsRequest::Type::UTIME`
     * * `FsRequest::Type::FUTIME`
     * * `FsRequest::Type::ACCESS`
     * * `FsRequest::Type::CHMOD`
     * * `FsRequest::Type::FCHMOD`
     * * `FsRequest::Type::FSYNC`
     * * `FsRequest::Type::FDATASYNC`
     * * `FsRequest::Type::UNLINK`
     * * `FsRequest::Type::RMDIR`
     * * `FsRequest::Type::MKDIR`
     * * `FsRequest::Type::MKDTEMP`
     * * `FsRequest::Type::RENAME`
     * * `FsRequest::Type::SCANDIR`
     * * `FsRequest::Type::LINK`
     * * `FsRequest::Type::SYMLINK`
     * * `FsRequest::Type::READLINK`
     * * `FsRequest::Type::CHOWN`
     * * `FsRequest::Type::FCHOWN`
     * * `FsRequest::Type::REALPATH`
     * * `FsRequest::Type::COPYFILE`
     * * `FsRequest::Type::LCHOWN`
     * * `FsRequest::Type::OPENDIR`
     * * `FsRequest::Type::READDIR`
     * * `FsRequest::Type::CLOSEDIR`
     * * `FsRequest::Type::STATFS`
     * * `FsRequest::Type::MKSTEMP`
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/fs.html#c.uv_fs_type)
     * for further details.
     */
    template<details::UVFsType e>
    struct FsEvent
    {
        FsEvent(const char *pathname) noexcept : path{ pathname }
        {
        }

        const char *path; /*!< The path affecting the request. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::READ`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::READ>
    {
        FsEvent(const char *pathname, std::unique_ptr<const char[]> buf, std::size_t sz) noexcept
            : path{ pathname }, data{ std::move(buf) }, size{ sz }
        {
        }

        const char *path;                   /*!< The path affecting the request. */
        std::unique_ptr<const char[]> data; /*!< A bunch of data read from the given path. */
        std::size_t size;                   /*!< The amount of data read from the given path. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::WRITE`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::WRITE>
    {
        FsEvent(const char *pathname, std::size_t sz) noexcept : path{ pathname }, size{ sz }
        {
        }

        const char *path; /*!< The path affecting the request. */
        std::size_t size; /*!< The amount of data written to the given path. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::SENDFILE`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::SENDFILE>
    {
        FsEvent(const char *pathname, std::size_t sz) noexcept : path{ pathname }, size{ sz }
        {
        }

        const char *path; /*!< The path affecting the request. */
        std::size_t size; /*!< The amount of data transferred. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::STAT`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::STAT>
    {
        FsEvent(const char *pathname, Stat curr) noexcept : path{ pathname }, stat{ std::move(curr) }
        {
        }

        const char *path; /*!< The path affecting the request. */
        Stat stat;        /*!< An initialized instance of Stat. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::FSTAT`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::FSTAT>
    {
        FsEvent(const char *pathname, Stat curr) noexcept : path{ pathname }, stat{ std::move(curr) }
        {
        }

        const char *path; /*!< The path affecting the request. */
        Stat stat;        /*!< An initialized instance of Stat. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::LSTAT`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::LSTAT>
    {
        FsEvent(const char *pathname, Stat curr) noexcept : path{ pathname }, stat{ std::move(curr) }
        {
        }

        const char *path; /*!< The path affecting the request. */
        Stat stat;        /*!< An initialized instance of Stat. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::STATFS`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::STATFS>
    {
        FsEvent(const char *pathname, Statfs curr) noexcept : path{ pathname }, statfs{ std::move(curr) }
        {
        }

        const char *path; /*!< The path affecting the request. */
        Statfs statfs;    /*!< An initialized instance of Statfs. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::MKSTEMP`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::MKSTEMP>
    {
        FsEvent(const char *pathname, std::size_t desc) noexcept : path{ pathname }, descriptor{ desc }
        {
        }

        const char *path;       /*!< The created file path. */
        std::size_t descriptor; /*!< The file descriptor as an integer. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::SCANDIR`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::SCANDIR>
    {
        FsEvent(const char *pathname, std::size_t sz) noexcept : path{ pathname }, size{ sz }
        {
        }

        const char *path; /*!< The path affecting the request. */
        std::size_t size; /*!< The number of directory entries selected. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::READLINK`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::READLINK>
    {
        explicit FsEvent(const char *pathname, const char *buf, std::size_t sz) noexcept : path{ pathname }, data{ buf }, size{ sz }
        {
        }

        const char *path; /*!< The path affecting the request. */
        const char *data; /*!< A bunch of data read from the given path. */
        std::size_t size; /*!< The amount of data read from the given path. */
    };

    /**
     * @brief FsEvent event specialization for `FsRequest::Type::READDIR`.
     *
     * It will be emitted by FsReq and/or FileReq according with their
     * functionalities.
     */
    template<>
    struct FsEvent<details::UVFsType::READDIR>
    {
        using EntryType = details::UVDirentTypeT;

        FsEvent(const char *name, EntryType type, bool eos) noexcept : name{ name }, type{ type }, eos{ eos }
        {
        }

        const char *name; /*!< The name of the last entry. */
        EntryType type;   /*!< The entry type. */
        bool eos;         /*!< True if there a no more entries to read. */
    };

    /**
     * @brief Base class for FsReq and/or FileReq.
     *
     * Not directly instantiable, should not be used by the users of the library.
     */
    template<typename T>
    class FsRequest : public Request<T, uv_fs_t>
    {
      protected:
        template<details::UVFsType e>
        static void fsGenericCallback(uv_fs_t *req)
        {
            auto ptr = Request<T, uv_fs_t>::reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<e>{ req->path });
            }
        }

        template<details::UVFsType e>
        static void fsResultCallback(uv_fs_t *req)
        {
            auto ptr = Request<T, uv_fs_t>::reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<e>{ req->path, static_cast<std::size_t>(req->result) });
            }
        }

        template<details::UVFsType e>
        static void fsStatCallback(uv_fs_t *req)
        {
            auto ptr = Request<T, uv_fs_t>::reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<e>{ req->path, req->statbuf });
            }
        }

        static void fsStatfsCallback(uv_fs_t *req)
        {
            auto ptr = Request<T, uv_fs_t>::reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<Type::STATFS>{ req->path, *static_cast<Statfs *>(req->ptr) });
            }
        }

        template<typename... Args>
        void cleanupAndInvoke(Args &&... args)
        {
            uv_fs_req_cleanup(this->get());
            this->invoke(std::forward<Args>(args)...);
        }

        template<typename F, typename... Args>
        void cleanupAndInvokeSync(F &&f, Args &&... args)
        {
            uv_fs_req_cleanup(this->get());
            std::forward<F>(f)(std::forward<Args>(args)..., nullptr);
        }

      public:
        using Time = std::chrono::duration<double>;
        using Type = details::UVFsType;
        using EntryType = details::UVDirentTypeT;

        using Request<T, uv_fs_t>::Request;
    };

    /**
     * @brief The FileReq request.
     *
     * Cross-platform sync and async filesystem operations.<br/>
     * All file operations are run on the threadpool.
     *
     * To create a `FileReq` through a `Loop`, no arguments are required.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/fs.html)
     * for further details.
     */
    class FileReq final : public FsRequest<FileReq>
    {
        static constexpr uv_file BAD_FD = -1;

        static void fsOpenCallback(uv_fs_t *req)
        {
            auto ptr = reserve(req);

            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->file = static_cast<uv_file>(req->result);
                ptr->publish(FsEvent<Type::OPEN>{ req->path });
            }
        }

        static void fsCloseCallback(uv_fs_t *req)
        {
            auto ptr = reserve(req);

            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->file = BAD_FD;
                ptr->publish(FsEvent<Type::CLOSE>{ req->path });
            }
        }

        static void fsReadCallback(uv_fs_t *req)
        {
            auto ptr = reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<Type::READ>{ req->path, std::move(ptr->current), static_cast<std::size_t>(req->result) });
            }
        }

      public:
        using FileOpen = details::UVFileOpenFlags;

        using FsRequest::FsRequest;

        ~FileReq() noexcept
        {
            uv_fs_req_cleanup(get());
        }

        /**
         * @brief Async [close](http://linux.die.net/man/2/close).
         *
         * Emit a `FsEvent<FileReq::Type::CLOSE>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         */
        void close()
        {
            cleanupAndInvoke(&uv_fs_close, parent(), get(), file, &fsCloseCallback);
        }

        /**
         * @brief Sync [close](http://linux.die.net/man/2/close).
         * @return True in case of success, false otherwise.
         */
        bool closeSync()
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_close, parent(), req, file);
            if (req->result >= 0)
            {
                file = BAD_FD;
            }
            return !(req->result < 0);
        }

        /**
         * @brief Async [open](http://linux.die.net/man/2/open).
         *
         * Emit a `FsEvent<FileReq::Type::OPEN>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * Available flags are:
         *
         * * `FileReq::FileOpen::APPEND`
         * * `FileReq::FileOpen::CREAT`
         * * `FileReq::FileOpen::DIRECT`
         * * `FileReq::FileOpen::DIRECTORY`
         * * `FileReq::FileOpen::DSYNC`
         * * `FileReq::FileOpen::EXCL`
         * * `FileReq::FileOpen::EXLOCK`
         * * `FileReq::FileOpen::FILEMAP`
         * * `FileReq::FileOpen::NOATIME`
         * * `FileReq::FileOpen::NOCTTY`
         * * `FileReq::FileOpen::NOFOLLOW`
         * * `FileReq::FileOpen::NONBLOCK`
         * * `FileReq::FileOpen::RANDOM`
         * * `FileReq::FileOpen::RDONLY`
         * * `FileReq::FileOpen::RDWR`
         * * `FileReq::FileOpen::SEQUENTIAL`
         * * `FileReq::FileOpen::SHORT_LIVED`
         * * `FileReq::FileOpen::SYMLINK`
         * * `FileReq::FileOpen::SYNC`
         * * `FileReq::FileOpen::TEMPORARY`
         * * `FileReq::FileOpen::TRUNC`
         * * `FileReq::FileOpen::WRONLY`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/fs.html#file-open-constants)
         * for further details.
         *
         * @param path A valid path name for a file.
         * @param flags Flags made out of underlying constants.
         * @param mode Mode, as described in the official documentation.
         */
        void open(std::string path, Flags<FileOpen> flags, int mode)
        {
            cleanupAndInvoke(&uv_fs_open, parent(), get(), path.data(), flags, mode, &fsOpenCallback);
        }

        /**
         * @brief Sync [open](http://linux.die.net/man/2/open).
         *
         * Available flags are:
         *
         * * `FileReq::FileOpen::APPEND`
         * * `FileReq::FileOpen::CREAT`
         * * `FileReq::FileOpen::DIRECT`
         * * `FileReq::FileOpen::DIRECTORY`
         * * `FileReq::FileOpen::DSYNC`
         * * `FileReq::FileOpen::EXCL`
         * * `FileReq::FileOpen::EXLOCK`
         * * `FileReq::FileOpen::FILEMAP`
         * * `FileReq::FileOpen::NOATIME`
         * * `FileReq::FileOpen::NOCTTY`
         * * `FileReq::FileOpen::NOFOLLOW`
         * * `FileReq::FileOpen::NONBLOCK`
         * * `FileReq::FileOpen::RANDOM`
         * * `FileReq::FileOpen::RDONLY`
         * * `FileReq::FileOpen::RDWR`
         * * `FileReq::FileOpen::SEQUENTIAL`
         * * `FileReq::FileOpen::SHORT_LIVED`
         * * `FileReq::FileOpen::SYMLINK`
         * * `FileReq::FileOpen::SYNC`
         * * `FileReq::FileOpen::TEMPORARY`
         * * `FileReq::FileOpen::TRUNC`
         * * `FileReq::FileOpen::WRONLY`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/fs.html#file-open-constants)
         * for further details.
         *
         * @param path A valid path name for a file.
         * @param flags Flags made out of underlying constants.
         * @param mode Mode, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool openSync(std::string path, Flags<FileOpen> flags, int mode)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_open, parent(), req, path.data(), flags, mode);
            if (req->result >= 0)
            {
                file = static_cast<uv_file>(req->result);
            }
            return !(req->result < 0);
        }

        /**
         * @brief Async [read](http://linux.die.net/man/2/preadv).
         *
         * Emit a `FsEvent<FileReq::Type::READ>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param offset Offset, as described in the official documentation.
         * @param len Length, as described in the official documentation.
         */
        void read(int64_t offset, unsigned int len)
        {
            current = std::unique_ptr<char[]>{ new char[len] };
            buffer = uv_buf_init(current.get(), len);
            uv_buf_t bufs[] = { buffer };
            cleanupAndInvoke(&uv_fs_read, parent(), get(), file, bufs, 1, offset, &fsReadCallback);
        }

        /**
         * @brief Sync [read](http://linux.die.net/man/2/preadv).
         *
         * @param offset Offset, as described in the official documentation.
         * @param len Length, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::pair` composed as it follows:
         *   * A bunch of data read from the given path.
         *   * The amount of data read from the given path.
         */
        std::pair<bool, std::pair<std::unique_ptr<const char[]>, std::size_t>> readSync(int64_t offset, unsigned int len)
        {
            current = std::unique_ptr<char[]>{ new char[len] };
            buffer = uv_buf_init(current.get(), len);
            uv_buf_t bufs[] = { buffer };
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_read, parent(), req, file, bufs, 1, offset);
            bool err = req->result < 0;
            return std::make_pair(!err, std::make_pair(std::move(current), err ? 0 : std::size_t(req->result)));
        }

        /**
         * @brief Async [write](http://linux.die.net/man/2/pwritev).
         *
         * The request takes the ownership of the data and it is in charge of delete
         * them.
         *
         * Emit a `FsEvent<FileReq::Type::WRITE>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param buf The data to be written.
         * @param len The lenght of the submitted data.
         * @param offset Offset, as described in the official documentation.
         */
        void write(std::unique_ptr<char[]> buf, unsigned int len, int64_t offset)
        {
            current = std::move(buf);
            uv_buf_t bufs[] = { uv_buf_init(current.get(), len) };
            cleanupAndInvoke(&uv_fs_write, parent(), get(), file, bufs, 1, offset, &fsResultCallback<Type::WRITE>);
        }

        /**
         * @brief Async [write](http://linux.die.net/man/2/pwritev).
         *
         * The request doesn't take the ownership of the data. Be sure that their
         * lifetime overcome the one of the request.
         *
         * Emit a `FsEvent<FileReq::Type::WRITE>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param buf The data to be written.
         * @param len The lenght of the submitted data.
         * @param offset Offset, as described in the official documentation.
         */
        void write(char *buf, unsigned int len, int64_t offset)
        {
            uv_buf_t bufs[] = { uv_buf_init(buf, len) };
            cleanupAndInvoke(&uv_fs_write, parent(), get(), file, bufs, 1, offset, &fsResultCallback<Type::WRITE>);
        }

        /**
         * @brief Sync [write](http://linux.die.net/man/2/pwritev).
         *
         * @param buf The data to be written.
         * @param len The lenght of the submitted data.
         * @param offset Offset, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * The amount of data written to the given path.
         */
        std::pair<bool, std::size_t> writeSync(std::unique_ptr<char[]> buf, unsigned int len, int64_t offset)
        {
            current = std::move(buf);
            uv_buf_t bufs[] = { uv_buf_init(current.get(), len) };
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_write, parent(), req, file, bufs, 1, offset);
            bool err = req->result < 0;
            return std::make_pair(!err, err ? 0 : std::size_t(req->result));
        }

        /**
         * @brief Async [fstat](http://linux.die.net/man/2/fstat).
         *
         * Emit a `FsEvent<FileReq::Type::FSTAT>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         */
        void stat()
        {
            cleanupAndInvoke(&uv_fs_fstat, parent(), get(), file, &fsStatCallback<Type::FSTAT>);
        }

        /**
         * @brief Sync [fstat](http://linux.die.net/man/2/fstat).
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * An initialized instance of Stat.
         */
        std::pair<bool, Stat> statSync()
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_fstat, parent(), req, file);
            return std::make_pair(!(req->result < 0), req->statbuf);
        }

        /**
         * @brief Async [fsync](http://linux.die.net/man/2/fsync).
         *
         * Emit a `FsEvent<FileReq::Type::FSYNC>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         */
        void sync()
        {
            cleanupAndInvoke(&uv_fs_fsync, parent(), get(), file, &fsGenericCallback<Type::FSYNC>);
        }

        /**
         * @brief Sync [fsync](http://linux.die.net/man/2/fsync).
         * @return True in case of success, false otherwise.
         */
        bool syncSync()
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_fsync, parent(), req, file);
            return !(req->result < 0);
        }

        /**
         * @brief Async [fdatasync](http://linux.die.net/man/2/fdatasync).
         *
         * Emit a `FsEvent<FileReq::Type::FDATASYNC>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         */
        void datasync()
        {
            cleanupAndInvoke(&uv_fs_fdatasync, parent(), get(), file, &fsGenericCallback<Type::FDATASYNC>);
        }

        /**
         * @brief Sync [fdatasync](http://linux.die.net/man/2/fdatasync).
         * @return True in case of success, false otherwise.
         */
        bool datasyncSync()
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_fdatasync, parent(), req, file);
            return !(req->result < 0);
        }

        /**
         * @brief Async [ftruncate](http://linux.die.net/man/2/ftruncate).
         *
         * Emit a `FsEvent<FileReq::Type::FTRUNCATE>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param offset Offset, as described in the official documentation.
         */
        void truncate(int64_t offset)
        {
            cleanupAndInvoke(&uv_fs_ftruncate, parent(), get(), file, offset, &fsGenericCallback<Type::FTRUNCATE>);
        }

        /**
         * @brief Sync [ftruncate](http://linux.die.net/man/2/ftruncate).
         * @param offset Offset, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool truncateSync(int64_t offset)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_ftruncate, parent(), req, file, offset);
            return !(req->result < 0);
        }

        /**
         * @brief Async [sendfile](http://linux.die.net/man/2/sendfile).
         *
         * Emit a `FsEvent<FileReq::Type::SENDFILE>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param out A valid instance of FileHandle.
         * @param offset Offset, as described in the official documentation.
         * @param length Length, as described in the official documentation.
         */
        void sendfile(FileHandle out, int64_t offset, std::size_t length)
        {
            cleanupAndInvoke(&uv_fs_sendfile, parent(), get(), out, file, offset, length, &fsResultCallback<Type::SENDFILE>);
        }

        /**
         * @brief Sync [sendfile](http://linux.die.net/man/2/sendfile).
         *
         * @param out A valid instance of FileHandle.
         * @param offset Offset, as described in the official documentation.
         * @param length Length, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * The amount of data transferred.
         */
        std::pair<bool, std::size_t> sendfileSync(FileHandle out, int64_t offset, std::size_t length)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_sendfile, parent(), req, out, file, offset, length);
            bool err = req->result < 0;
            return std::make_pair(!err, err ? 0 : std::size_t(req->result));
        }

        /**
         * @brief Async [fchmod](http://linux.die.net/man/2/fchmod).
         *
         * Emit a `FsEvent<FileReq::Type::FCHMOD>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param mode Mode, as described in the official documentation.
         */
        void chmod(int mode)
        {
            cleanupAndInvoke(&uv_fs_fchmod, parent(), get(), file, mode, &fsGenericCallback<Type::FCHMOD>);
        }

        /**
         * @brief Sync [fchmod](http://linux.die.net/man/2/fchmod).
         * @param mode Mode, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool chmodSync(int mode)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_fchmod, parent(), req, file, mode);
            return !(req->result < 0);
        }

        /**
         * @brief Async [futime](http://linux.die.net/man/2/futime).
         *
         * Emit a `FsEvent<FileReq::Type::FUTIME>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param atime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @param mtime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         */
        void utime(Time atime, Time mtime)
        {
            cleanupAndInvoke(&uv_fs_futime, parent(), get(), file, atime.count(), mtime.count(), &fsGenericCallback<Type::FUTIME>);
        }

        /**
         * @brief Sync [futime](http://linux.die.net/man/2/futime).
         * @param atime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @param mtime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool utimeSync(Time atime, Time mtime)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_futime, parent(), req, file, atime.count(), mtime.count());
            return !(req->result < 0);
        }

        /**
         * @brief Async [fchown](http://linux.die.net/man/2/fchown).
         *
         * Emit a `FsEvent<FileReq::Type::FCHOWN>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         */
        void chown(Uid uid, Gid gid)
        {
            cleanupAndInvoke(&uv_fs_fchown, parent(), get(), file, uid, gid, &fsGenericCallback<Type::FCHOWN>);
        }

        /**
         * @brief Sync [fchown](http://linux.die.net/man/2/fchown).
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool chownSync(Uid uid, Gid gid)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_fchown, parent(), req, file, uid, gid);
            return !(req->result < 0);
        }

        /**
         * @brief Cast operator to FileHandle.
         *
         * Cast operator to an internal representation of the underlying file
         * handle.
         *
         * @return A valid instance of FileHandle (the descriptor can be invalid).
         */
        operator FileHandle() const noexcept
        {
            return file;
        }

      private:
        std::unique_ptr<char[]> current{ nullptr };
        uv_buf_t buffer{};
        uv_file file{ BAD_FD };
    };

    /**
     * @brief The FsReq request.
     *
     * Cross-platform sync and async filesystem operations.<br/>
     * All file operations are run on the threadpool.
     *
     * To create a `FsReq` through a `Loop`, no arguments are required.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/fs.html)
     * for further details.
     */
    class FsReq final : public FsRequest<FsReq>
    {
        static void fsReadlinkCallback(uv_fs_t *req)
        {
            auto ptr = reserve(req);
            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                ptr->publish(FsEvent<Type::READLINK>{ req->path, static_cast<char *>(req->ptr), static_cast<std::size_t>(req->result) });
            }
        }

        static void fsReaddirCallback(uv_fs_t *req)
        {
            auto ptr = reserve(req);

            if (req->result < 0)
            {
                ptr->publish(ErrorEvent{ req->result });
            }
            else
            {
                auto *dir = static_cast<uv_dir_t *>(req->ptr);
                ptr->publish(FsEvent<Type::READDIR>{ dir->dirents[0].name, static_cast<EntryType>(dir->dirents[0].type), !req->result });
            }
        }

      public:
        using CopyFile = details::UVCopyFileFlags;
        using SymLink = details::UVSymLinkFlags;

        using FsRequest::FsRequest;

        ~FsReq() noexcept
        {
            uv_fs_req_cleanup(get());
        }

        /**
         * @brief Async [unlink](http://linux.die.net/man/2/unlink).
         *
         * Emit a `FsEvent<FsReq::Type::UNLINK>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void unlink(std::string path)
        {
            cleanupAndInvoke(&uv_fs_unlink, parent(), get(), path.data(), &fsGenericCallback<Type::UNLINK>);
        }

        /**
         * @brief Sync [unlink](http://linux.die.net/man/2/unlink).
         * @param path Path, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool unlinkSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_unlink, parent(), req, path.data());
            return !(req->result < 0);
        }

        /**
         * @brief Async [mkdir](http://linux.die.net/man/2/mkdir).
         *
         * Emit a `FsEvent<FsReq::Type::MKDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         */
        void mkdir(std::string path, int mode)
        {
            cleanupAndInvoke(&uv_fs_mkdir, parent(), get(), path.data(), mode, &fsGenericCallback<Type::MKDIR>);
        }

        /**
         * @brief Sync [mkdir](http://linux.die.net/man/2/mkdir).
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool mkdirSync(std::string path, int mode)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_mkdir, parent(), req, path.data(), mode);
            return !(req->result < 0);
        }

        /**
         * @brief Async [mktemp](http://linux.die.net/man/3/mkdtemp).
         *
         * Emit a `FsEvent<FsReq::Type::MKDTEMP>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param tpl Template, as described in the official documentation.
         */
        void mkdtemp(std::string tpl)
        {
            cleanupAndInvoke(&uv_fs_mkdtemp, parent(), get(), tpl.data(), &fsGenericCallback<Type::MKDTEMP>);
        }

        /**
         * @brief Sync [mktemp](http://linux.die.net/man/3/mkdtemp).
         *
         * @param tpl Template, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * The actual path of the newly created directory.
         */
        std::pair<bool, const char *> mkdtempSync(std::string tpl)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_mkdtemp, parent(), req, tpl.data());
            return std::make_pair(!(req->result < 0), req->path);
        }

        /**
         * @brief Async [mkstemp](https://linux.die.net/man/3/mkstemp).
         *
         * Emit a `FsEvent<FsReq::Type::MKSTEMP>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param tpl Template, as described in the official documentation.
         */
        void mkstemp(std::string tpl)
        {
            cleanupAndInvoke(&uv_fs_mkstemp, parent(), get(), tpl.data(), &fsResultCallback<Type::MKSTEMP>);
        }

        /**
         * @brief Sync [mkstemp](https://linux.die.net/man/3/mkstemp).
         *
         * Returns a composed value where:
         *
         * * The first parameter indicates the created file path.
         * * The second parameter is the file descriptor as an integer.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/fs.html#c.uv_fs_mkstemp)
         * for further details.
         *
         * @param tpl Template, as described in the official documentation.
         *
         * @return A pair where:

         * * The first parameter is a boolean value that is true in case of success,
         * false otherwise.
         * * The second parameter is a composed value (see above).
         */
        std::pair<bool, std::pair<std::string, std::size_t>> mkstempSync(std::string tpl)
        {
            std::pair<bool, std::pair<std::string, std::size_t>> ret{ false, {} };
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_mkdtemp, parent(), req, tpl.data());
            ret.first = !(req->result < 0);

            if (ret.first)
            {
                ret.second.first = req->path;
                ret.second.second = static_cast<std::size_t>(req->result);
            }

            return ret;
        }

        /**
         * @brief Async [rmdir](http://linux.die.net/man/2/rmdir).
         *
         * Emit a `FsEvent<FsReq::Type::RMDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void rmdir(std::string path)
        {
            cleanupAndInvoke(&uv_fs_rmdir, parent(), get(), path.data(), &fsGenericCallback<Type::RMDIR>);
        }

        /**
         * @brief Sync [rmdir](http://linux.die.net/man/2/rmdir).
         * @param path Path, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool rmdirSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_rmdir, parent(), req, path.data());
            return !(req->result < 0);
        }

        /**
         * @brief Async [scandir](http://linux.die.net/man/3/scandir).
         *
         * Emit a `FsEvent<FsReq::Type::SCANDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param flags Flags, as described in the official documentation.
         */
        void scandir(std::string path, int flags)
        {
            cleanupAndInvoke(&uv_fs_scandir, parent(), get(), path.data(), flags, &fsResultCallback<Type::SCANDIR>);
        }

        /**
         * @brief Sync [scandir](http://linux.die.net/man/3/scandir).
         *
         * @param path Path, as described in the official documentation.
         * @param flags Flags, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * The number of directory entries selected.
         */
        std::pair<bool, std::size_t> scandirSync(std::string path, int flags)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_scandir, parent(), req, path.data(), flags);
            bool err = req->result < 0;
            return std::make_pair(!err, err ? 0 : std::size_t(req->result));
        }

        /**
         * @brief Gets entries populated with the next directory entry data.
         *
         * Returns a composed value where:
         *
         * * The first parameter indicates the entry type (see below).
         * * The second parameter is a string that contains the actual value.
         *
         * Available entry types are:
         *
         * * `FsReq::EntryType::UNKNOWN`
         * * `FsReq::EntryType::FILE`
         * * `FsReq::EntryType::DIR`
         * * `FsReq::EntryType::LINK`
         * * `FsReq::EntryType::FIFO`
         * * `FsReq::EntryType::SOCKET`
         * * `FsReq::EntryType::CHAR`
         * * `FsReq::EntryType::BLOCK`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/fs.html#c.uv_dirent_t)
         * for further details.
         *
         * @return A pair where:
         *
         * * The first parameter is a boolean value that indicates if the current
         * entry is still valid.
         * * The second parameter is a composed value (see above).
         */
        std::pair<bool, std::pair<EntryType, const char *>> scandirNext()
        {
            std::pair<bool, std::pair<EntryType, const char *>> ret{ false, { EntryType::UNKNOWN, nullptr } };

            // we cannot use cleanupAndInvokeSync because of the return value of
            // uv_fs_scandir_next
            uv_fs_req_cleanup(get());
            auto res = uv_fs_scandir_next(get(), dirents);

            if (UV_EOF != res)
            {
                ret.second.first = static_cast<EntryType>(dirents[0].type);
                ret.second.second = dirents[0].name;
                ret.first = true;
            }

            return ret;
        }

        /**
         * @brief Async [stat](http://linux.die.net/man/2/stat).
         *
         * Emit a `FsEvent<FsReq::Type::STAT>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void stat(std::string path)
        {
            cleanupAndInvoke(&uv_fs_stat, parent(), get(), path.data(), &fsStatCallback<Type::STAT>);
        }

        /**
         * @brief Sync [stat](http://linux.die.net/man/2/stat).
         *
         * @param path Path, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * An initialized instance of Stat.
         */
        std::pair<bool, Stat> statSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_stat, parent(), req, path.data());
            return std::make_pair(!(req->result < 0), req->statbuf);
        }

        /**
         * @brief Async [lstat](http://linux.die.net/man/2/lstat).
         *
         * Emit a `FsEvent<FsReq::Type::LSTAT>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void lstat(std::string path)
        {
            cleanupAndInvoke(&uv_fs_lstat, parent(), get(), path.data(), &fsStatCallback<Type::LSTAT>);
        }

        /**
         * @brief Sync [lstat](http://linux.die.net/man/2/lstat).
         *
         * @param path Path, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * An initialized instance of Stat.
         */
        std::pair<bool, Stat> lstatSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_lstat, parent(), req, path.data());
            return std::make_pair(!(req->result < 0), req->statbuf);
        }

        /**
         * @brief Async [statfs](http://linux.die.net/man/2/statfs).
         *
         * Emit a `FsEvent<FsReq::Type::STATFS>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * Any fields in the resulting object that are not supported by the
         * underlying operating system are set to zero.
         *
         * @param path Path, as described in the official documentation.
         */
        void stasfs(std::string path)
        {
            cleanupAndInvoke(&uv_fs_statfs, parent(), get(), path.data(), &fsStatfsCallback);
        }

        /**
         * @brief Sync [statfs](http://linux.die.net/man/2/statfs).
         *
         * Any fields in the resulting object that are not supported by the
         * underlying operating system are set to zero.
         *
         * @param path Path, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * An initialized instance of Statfs.
         */
        std::pair<bool, Statfs> statfsSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_statfs, parent(), req, path.data());
            return std::make_pair(!(req->result < 0), *static_cast<uv_statfs_t *>(req->ptr));
        }

        /**
         * @brief Async [rename](http://linux.die.net/man/2/rename).
         *
         * Emit a `FsEvent<FsReq::Type::RENAME>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         */
        void rename(std::string old, std::string path)
        {
            cleanupAndInvoke(&uv_fs_rename, parent(), get(), old.data(), path.data(), &fsGenericCallback<Type::RENAME>);
        }

        /**
         * @brief Sync [rename](http://linux.die.net/man/2/rename).
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool renameSync(std::string old, std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_rename, parent(), req, old.data(), path.data());
            return !(req->result < 0);
        }

        /**
         * @brief Copies a file asynchronously from a path to a new one.
         *
         * Emit a `FsEvent<FsReq::Type::UV_FS_COPYFILE>` event when
         * completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * Available flags are:
         *
         * * `FsReq::CopyFile::EXCL`: it fails if the destination path
         * already exists (the default behavior is to overwrite the destination if
         * it exists).
         * * `FsReq::CopyFile::FICLONE`: If present, it will attempt to create a
         * copy-on-write reflink. If the underlying platform does not support
         * copy-on-write, then a fallback copy mechanism is used.
         * * `FsReq::CopyFile::FICLONE_FORCE`: If present, it will attempt to create
         * a copy-on-write reflink. If the underlying platform does not support
         * copy-on-write, then an error is returned.
         *
         * @warning
         * If the destination path is created, but an error occurs while copying the
         * data, then the destination path is removed. There is a brief window of
         * time between closing and removing the file where another process could
         * access the file.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @param flags Optional additional flags.
         */
        void copyfile(std::string old, std::string path, Flags<CopyFile> flags = Flags<CopyFile>{})
        {
            cleanupAndInvoke(&uv_fs_copyfile, parent(), get(), old.data(), path.data(), flags, &fsGenericCallback<Type::COPYFILE>);
        }

        /**
         * @brief Copies a file synchronously from a path to a new one.
         *
         * Available flags are:
         *
         * * `FsReq::CopyFile::EXCL`: it fails if the destination path
         * already exists (the default behavior is to overwrite the destination if
         * it exists).
         *
         * If the destination path is created, but an error occurs while copying the
         * data, then the destination path is removed. There is a brief window of
         * time between closing and removing the file where another process could
         * access the file.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @param flags Optional additional flags.
         * @return True in case of success, false otherwise.
         */
        bool copyfileSync(std::string old, std::string path, Flags<CopyFile> flags = Flags<CopyFile>{})
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_copyfile, parent(), get(), old.data(), path.data(), flags);
            return !(req->result < 0);
        }

        /**
         * @brief Async [access](http://linux.die.net/man/2/access).
         *
         * Emit a `FsEvent<FsReq::Type::ACCESS>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         */
        void access(std::string path, int mode)
        {
            cleanupAndInvoke(&uv_fs_access, parent(), get(), path.data(), mode, &fsGenericCallback<Type::ACCESS>);
        }

        /**
         * @brief Sync [access](http://linux.die.net/man/2/access).
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool accessSync(std::string path, int mode)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_access, parent(), req, path.data(), mode);
            return !(req->result < 0);
        }

        /**
         * @brief Async [chmod](http://linux.die.net/man/2/chmod).
         *
         * Emit a `FsEvent<FsReq::Type::CHMOD>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         */
        void chmod(std::string path, int mode)
        {
            cleanupAndInvoke(&uv_fs_chmod, parent(), get(), path.data(), mode, &fsGenericCallback<Type::CHMOD>);
        }

        /**
         * @brief Sync [chmod](http://linux.die.net/man/2/chmod).
         * @param path Path, as described in the official documentation.
         * @param mode Mode, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool chmodSync(std::string path, int mode)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_chmod, parent(), req, path.data(), mode);
            return !(req->result < 0);
        }

        /**
         * @brief Async [utime](http://linux.die.net/man/2/utime).
         *
         * Emit a `FsEvent<FsReq::Type::UTIME>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param atime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @param mtime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         */
        void utime(std::string path, Time atime, Time mtime)
        {
            cleanupAndInvoke(&uv_fs_utime, parent(), get(), path.data(), atime.count(), mtime.count(), &fsGenericCallback<Type::UTIME>);
        }

        /**
         * @brief Sync [utime](http://linux.die.net/man/2/utime).
         * @param path Path, as described in the official documentation.
         * @param atime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @param mtime `std::chrono::duration<double>`, having the same meaning as
         * described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool utimeSync(std::string path, Time atime, Time mtime)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_utime, parent(), req, path.data(), atime.count(), mtime.count());
            return !(req->result < 0);
        }

        /**
         * @brief Async [link](http://linux.die.net/man/2/link).
         *
         * Emit a `FsEvent<FsReq::Type::LINK>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         */
        void link(std::string old, std::string path)
        {
            cleanupAndInvoke(&uv_fs_link, parent(), get(), old.data(), path.data(), &fsGenericCallback<Type::LINK>);
        }

        /**
         * @brief Sync [link](http://linux.die.net/man/2/link).
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool linkSync(std::string old, std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_link, parent(), req, old.data(), path.data());
            return !(req->result < 0);
        }

        /**
         * @brief Async [symlink](http://linux.die.net/man/2/symlink).
         *
         * Emit a `FsEvent<FsReq::Type::SYMLINK>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * Available flags are:
         *
         * * `FsReq::SymLink::DIR`: it indicates that the old path points to a
         * directory.
         * * `FsReq::SymLink::JUNCTION`: it requests that the symlink is created
         * using junction points.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @param flags Optional additional flags.
         */
        void symlink(std::string old, std::string path, Flags<SymLink> flags = Flags<SymLink>{})
        {
            cleanupAndInvoke(&uv_fs_symlink, parent(), get(), old.data(), path.data(), flags, &fsGenericCallback<Type::SYMLINK>);
        }

        /**
         * @brief Sync [symlink](http://linux.die.net/man/2/symlink).
         *
         * Available flags are:
         *
         * * `FsReq::SymLink::DIR`: it indicates that the old path points to a
         * directory.
         * * `FsReq::SymLink::JUNCTION`: it requests that the symlink is created
         * using junction points.
         *
         * @param old Old path, as described in the official documentation.
         * @param path New path, as described in the official documentation.
         * @param flags Flags, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool symlinkSync(std::string old, std::string path, Flags<SymLink> flags = Flags<SymLink>{})
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_symlink, parent(), req, old.data(), path.data(), flags);
            return !(req->result < 0);
        }

        /**
         * @brief Async [readlink](http://linux.die.net/man/2/readlink).
         *
         * Emit a `FsEvent<FsReq::Type::READLINK>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void readlink(std::string path)
        {
            cleanupAndInvoke(&uv_fs_readlink, parent(), get(), path.data(), &fsReadlinkCallback);
        }

        /**
         * @brief Sync [readlink](http://linux.die.net/man/2/readlink).
         *
         * @param path Path, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * A `std::pair` composed as it follows:
         *   * A bunch of data read from the given path.
         *   * The amount of data read from the given path.
         */
        std::pair<bool, std::pair<const char *, std::size_t>> readlinkSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_readlink, parent(), req, path.data());
            bool err = req->result < 0;
            return std::make_pair(!err, std::make_pair(static_cast<char *>(req->ptr), err ? 0 : std::size_t(req->result)));
        }

        /**
         * @brief Async [realpath](http://linux.die.net/man/3/realpath).
         *
         * Emit a `FsEvent<FsReq::Type::REALPATH>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         */
        void realpath(std::string path)
        {
            cleanupAndInvoke(&uv_fs_realpath, parent(), get(), path.data(), &fsGenericCallback<Type::REALPATH>);
        }

        /**
         * @brief Sync [realpath](http://linux.die.net/man/3/realpath).
         *
         * @param path Path, as described in the official documentation.
         *
         * @return A `std::pair` composed as it follows:
         * * A boolean value that is true in case of success, false otherwise.
         * * The canonicalized absolute pathname.
         */
        std::pair<bool, const char *> realpathSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_realpath, parent(), req, path.data());
            return std::make_pair(!(req->result < 0), req->path);
        }

        /**
         * @brief Async [chown](http://linux.die.net/man/2/chown).
         *
         * Emit a `FsEvent<FsReq::Type::CHOWN>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         */
        void chown(std::string path, Uid uid, Gid gid)
        {
            cleanupAndInvoke(&uv_fs_chown, parent(), get(), path.data(), uid, gid, &fsGenericCallback<Type::CHOWN>);
        }

        /**
         * @brief Sync [chown](http://linux.die.net/man/2/chown).
         * @param path Path, as described in the official documentation.
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool chownSync(std::string path, Uid uid, Gid gid)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_chown, parent(), req, path.data(), uid, gid);
            return !(req->result < 0);
        }

        /**
         * @brief Async [lchown](https://linux.die.net/man/2/lchown).
         *
         * Emit a `FsEvent<FsReq::Type::LCHOWN>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * @param path Path, as described in the official documentation.
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         */
        void lchown(std::string path, Uid uid, Gid gid)
        {
            cleanupAndInvoke(&uv_fs_lchown, parent(), get(), path.data(), uid, gid, &fsGenericCallback<Type::LCHOWN>);
        }

        /**
         * @brief Sync [lchown](https://linux.die.net/man/2/lchown).
         * @param path Path, as described in the official documentation.
         * @param uid UID, as described in the official documentation.
         * @param gid GID, as described in the official documentation.
         * @return True in case of success, false otherwise.
         */
        bool lchownSync(std::string path, Uid uid, Gid gid)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_lchown, parent(), req, path.data(), uid, gid);
            return !(req->result < 0);
        }

        /**
         * @brief Opens a path asynchronously as a directory stream.
         *
         * Emit a `FsEvent<FsReq::Type::OPENDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * The contents of the directory can be iterated over by means of the
         * `readdir` od `readdirSync` member functions. The memory allocated by this
         * function must be freed by calling `closedir` or `closedirSync`.
         *
         * @param path The path to open as a directory stream.
         */
        void opendir(std::string path)
        {
            cleanupAndInvoke(&uv_fs_opendir, parent(), get(), path.data(), &fsGenericCallback<Type::OPENDIR>);
        }

        /**
         * @brief Opens a path synchronously as a directory stream.
         *
         * The contents of the directory can be iterated over by means of the
         * `readdir` od `readdirSync` member functions. The memory allocated by this
         * function must be freed by calling `closedir` or `closedirSync`.
         *
         * @param path The path to open as a directory stream.
         * @return True in case of success, false otherwise.
         */
        bool opendirSync(std::string path)
        {
            auto req = get();
            cleanupAndInvokeSync(&uv_fs_opendir, parent(), req, path.data());
            return !(req->result < 0);
        }

        /**
         * @brief Closes asynchronously a directory stream.
         *
         * Emit a `FsEvent<FsReq::Type::CLOSEDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * It frees also the memory allocated internally when a path has been opened
         * as a directory stream.
         */
        void closedir()
        {
            auto req = get();
            auto *dir = static_cast<uv_dir_t *>(req->ptr);
            cleanupAndInvoke(&uv_fs_closedir, parent(), req, dir, &fsGenericCallback<Type::CLOSEDIR>);
        }

        /**
         * @brief Closes synchronously a directory stream.
         *
         * It frees also the memory allocated internally when a path has been opened
         * as a directory stream.
         *
         * @return True in case of success, false otherwise.
         */
        bool closedirSync()
        {
            auto req = get();
            auto *dir = static_cast<uv_dir_t *>(req->ptr);
            cleanupAndInvokeSync(&uv_fs_closedir, parent(), req, dir);
            return !(req->result < 0);
        }

        /**
         * @brief Iterates asynchronously over a directory stream one entry at a
         * time.
         *
         * Emit a `FsEvent<FsReq::Type::READDIR>` event when completed.<br/>
         * Emit an ErrorEvent event in case of errors.
         *
         * This function isn't thread safe. Moreover, it doesn't return the `.` and
         * `..` entries.
         */
        void readdir()
        {
            auto req = get();
            auto *dir = static_cast<uv_dir_t *>(req->ptr);
            dir->dirents = dirents;
            dir->nentries = 1;
            cleanupAndInvoke(&uv_fs_readdir, parent(), req, dir, &fsReaddirCallback);
        }

        /**
         * @brief Iterates synchronously over a directory stream one entry at a
         * time.
         *
         * Returns a composed value where:
         *
         * * The first parameter indicates the entry type (see below).
         * * The second parameter is a string that contains the actual value.
         *
         * Available entry types are:
         *
         * * `FsReq::EntryType::UNKNOWN`
         * * `FsReq::EntryType::FILE`
         * * `FsReq::EntryType::DIR`
         * * `FsReq::EntryType::LINK`
         * * `FsReq::EntryType::FIFO`
         * * `FsReq::EntryType::SOCKET`
         * * `FsReq::EntryType::CHAR`
         * * `FsReq::EntryType::BLOCK`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/fs.html#c.uv_dirent_t)
         * for further details.
         *
         * This function isn't thread safe. Moreover, it doesn't return the `.` and
         * `..` entries.
         *
         * @return A pair where:
         *
         * * The first parameter is a boolean value that indicates if the current
         * entry is still valid.
         * * The second parameter is a composed value (see above).
         */
        std::pair<bool, std::pair<EntryType, const char *>> readdirSync()
        {
            auto req = get();
            auto *dir = static_cast<uv_dir_t *>(req->ptr);
            dir->dirents = dirents;
            dir->nentries = 1;
            cleanupAndInvokeSync(&uv_fs_readdir, parent(), req, dir);
            return { req->result != 0, { static_cast<EntryType>(dirents[0].type), dirents[0].name } };
        }

      private:
        uv_dirent_t dirents[1];
    };

    /*! @brief Helper functions. */
    struct FsHelper
    {
        /**
         * @brief Gets the OS dependent handle.
         *
         * For a file descriptor in the C runtime, get the OS-dependent handle. On
         * UNIX, returns the file descriptor as-is. On Windows, this calls a system
         * function.<br/>
         * Note that the return value is still owned by the C runtime, any attempts
         * to close it or to use it after closing the file descriptor may lead to
         * malfunction.
         */
        static OSFileDescriptor handle(FileHandle file) noexcept
        {
            return uv_get_osfhandle(file);
        }

        /**
         * @brief Gets the file descriptor.
         *
         * For a OS-dependent handle, get the file descriptor in the C runtime. On
         * UNIX, returns the file descriptor as-is. On Windows, this calls a system
         * function.<br/>
         * Note that the return value is still owned by the C runtime, any attempts
         * to close it or to use it after closing the handle may lead to
         * malfunction.
         */
        static FileHandle open(OSFileDescriptor descriptor) noexcept
        {
            return uv_open_osfhandle(descriptor);
        }
    };

} // namespace uvw

/*-- #include "uvw/fs.hpp" end --*/
/*-- #include "uvw/fs_event.hpp" start --*/

#include <memory>
#include <string>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVFsEventFlags : std::underlying_type_t<uv_fs_event_flags>
        {
            WATCH_ENTRY = UV_FS_EVENT_WATCH_ENTRY,
            STAT = UV_FS_EVENT_STAT,
            RECURSIVE = UV_FS_EVENT_RECURSIVE
        };

        enum class UVFsEvent : std::underlying_type_t<uv_fs_event>
        {
            RENAME = UV_RENAME,
            CHANGE = UV_CHANGE
        };

    } // namespace details

    /**
     * @brief FsEventEvent event.
     *
     * It will be emitted by FsEventHandle according with its functionalities.
     */
    struct FsEventEvent
    {
        FsEventEvent(const char *pathname, Flags<details::UVFsEvent> events) : filename{ pathname }, flags{ std::move(events) }
        {
        }

        /**
         * @brief The path to the file being monitored.
         *
         * If the handle was started with a directory, the filename parameter will
         * be a relative path to a file contained in the directory.
         */
        const char *filename;

        /**
         * @brief Detected events all in one.
         *
         * Available flags are:
         *
         * * `FsEventHandle::Watch::RENAME`
         * * `FsEventHandle::Watch::CHANGE`
         */
        Flags<details::UVFsEvent> flags;
    };

    /**
     * @brief The FsEventHandle handle.
     *
     * These handles allow the user to monitor a given path for changes, for
     * example, if the file was renamed or there was a generic change in it. The
     * best backend for the job on each platform is chosen by the handle.
     *
     * To create a `FsEventHandle` through a `Loop`, no arguments are required.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/fs_event.html)
     * for further details.
     */
    class FsEventHandle final : public Handle<FsEventHandle, uv_fs_event_t>
    {
        static void startCallback(uv_fs_event_t *handle, const char *filename, int events, int status)
        {
            FsEventHandle &fsEvent = *(static_cast<FsEventHandle *>(handle->data));
            if (status)
            {
                fsEvent.publish(ErrorEvent{ status });
            }
            else
            {
                fsEvent.publish(FsEventEvent{ filename, static_cast<std::underlying_type_t<details::UVFsEvent>>(events) });
            }
        }

      public:
        using Watch = details::UVFsEvent;
        using Event = details::UVFsEventFlags;

        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_fs_event_init);
        }

        /**
         * @brief Starts watching the specified path.
         *
         * It will watch the specified path for changes.<br/>
         * As soon as a change is observed, a FsEventEvent is emitted by the
         * handle.<br>
         * It could happen that ErrorEvent events are emitted while running.
         *
         * Available flags are:
         *
         * * `FsEventHandle::Event::WATCH_ENTRY`
         * * `FsEventHandle::Event::STAT`
         * * `FsEventHandle::Event::RECURSIVE`
         *
         * @param path The file or directory to be monitored.
         * @param flags Additional flags to control the behavior.
         */
        void start(std::string path, Flags<Event> flags = Flags<Event>{})
        {
            invoke(&uv_fs_event_start, get(), &startCallback, path.data(), flags);
        }

        /**
         * @brief Starts watching the specified path.
         *
         * It will watch the specified path for changes.<br/>
         * As soon as a change is observed, a FsEventEvent is emitted by the
         * handle.<br>
         * It could happen that ErrorEvent events are emitted while running.
         *
         * Available flags are:
         *
         * * `FsEventHandle::Event::WATCH_ENTRY`
         * * `FsEventHandle::Event::STAT`
         * * `FsEventHandle::Event::RECURSIVE`
         *
         * @param path The file or directory to be monitored.
         * @param flag Additional flag to control the behavior.
         */
        void start(std::string path, Event flag)
        {
            start(std::move(path), Flags<Event>{ flag });
        }

        /**
         * @brief Stops polling the file descriptor.
         */
        void stop()
        {
            invoke(&uv_fs_event_stop, get());
        }

        /**
         * @brief Gets the path being monitored.
         * @return The path being monitored, an empty string in case of errors.
         */
        std::string path() noexcept
        {
            return details::tryRead(&uv_fs_event_getpath, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/fs_event.hpp" end --*/
/*-- #include "uvw/fs_poll.hpp" start --*/

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief FsPollEvent event.
     *
     * It will be emitted by FsPollHandle according with its functionalities.
     */
    struct FsPollEvent
    {
        explicit FsPollEvent(Stat previous, Stat current) noexcept : prev{ std::move(previous) }, curr{ std::move(current) }
        {
        }

        Stat prev; /*!< The old Stat struct. */
        Stat curr; /*!< The new Stat struct. */
    };

    /**
     * @brief The FsPollHandle handle.
     *
     * It allows the user to monitor a given path for changes. Unlike FsEventHandle
     * handles, FsPollHandle handles use stat to detect when a file has changed so
     * they can work on file systems where FsEventHandle handles can’t.
     *
     * To create a `FsPollHandle` through a `Loop`, no arguments are required.
     */
    class FsPollHandle final : public Handle<FsPollHandle, uv_fs_poll_t>
    {
        static void startCallback(uv_fs_poll_t *handle, int status, const uv_stat_t *prev, const uv_stat_t *curr)
        {
            FsPollHandle &fsPoll = *(static_cast<FsPollHandle *>(handle->data));
            if (status)
            {
                fsPoll.publish(ErrorEvent{ status });
            }
            else
            {
                fsPoll.publish(FsPollEvent{ *prev, *curr });
            }
        }

      public:
        using Time = std::chrono::duration<unsigned int, std::milli>;

        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_fs_poll_init);
        }

        /**
         * @brief Starts the handle.
         *
         * The handle will start emitting FsPollEvent when needed.
         *
         * @param file The path to the file to be checked.
         * @param interval Milliseconds between successive checks.
         */
        void start(std::string file, Time interval)
        {
            invoke(&uv_fs_poll_start, get(), &startCallback, file.data(), interval.count());
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_fs_poll_stop, get());
        }

        /**
         * @brief Gets the path being monitored by the handle.
         * @return The path being monitored by the handle, an empty string in case
         * of errors.
         */
        std::string path() noexcept
        {
            return details::tryRead(&uv_fs_poll_getpath, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/fs_poll.hpp" end --*/
/*-- #include "uvw/idle.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief IdleEvent event.
     *
     * It will be emitted by IdleHandle according with its functionalities.
     */
    struct IdleEvent
    {
    };

    /**
     * @brief The IdleHandle handle.
     *
     * Idle handles will emit a IdleEvent event once per loop iteration, right
     * before the PrepareHandle handles.
     *
     * The notable difference with prepare handles is that when there are active
     * idle handles, the loop will perform a zero timeout poll instead of blocking
     * for I/O.
     *
     * @note
     * Despite the name, idle handles will emit events on every loop iteration, not
     * when the loop is actually _idle_.
     *
     * To create an `IdleHandle` through a `Loop`, no arguments are required.
     */
    class IdleHandle final : public Handle<IdleHandle, uv_idle_t>
    {
        static void startCallback(uv_idle_t *handle)
        {
            IdleHandle &idle = *(static_cast<IdleHandle *>(handle->data));
            idle.publish(IdleEvent{});
        }

      public:
        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_idle_init);
        }

        /**
         * @brief Starts the handle.
         *
         * A IdleEvent event will be emitted once per loop iteration, right before
         * polling the PrepareHandle handles.
         */
        void start()
        {
            invoke(&uv_idle_start, get(), &startCallback);
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_idle_stop, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/idle.hpp" end --*/
/*-- #include "uvw/lib.hpp" start --*/

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/
/*-- #include "uvw/underlying_type.hpp" start --*/
/*-- #include "uvw/underlying_type.hpp" end --*/

namespace uvw
{

    /**
     * @brief The SharedLib class.
     *
     * `uvw` provides cross platform utilities for loading shared libraries and
     * retrieving symbols from them, by means of the API offered by `libuv`.
     */
    class SharedLib final : public UnderlyingType<SharedLib, uv_lib_t>
    {
      public:
        explicit SharedLib(ConstructorAccess ca, std::shared_ptr<Loop> ref, std::string filename) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            opened = (0 == uv_dlopen(filename.data(), get()));
        }

        ~SharedLib() noexcept
        {
            uv_dlclose(get());
        }

        /**
         * @brief Checks if the library has been correctly opened.
         * @return True if the library is opened, false otherwise.
         */
        explicit operator bool() const noexcept
        {
            return opened;
        }

        /**
         * @brief Retrieves a data pointer from a dynamic library.
         *
         * `F` shall be a valid function type (as an example, `void(int)`).<br/>
         * It is legal for a symbol to map to `nullptr`.
         *
         * @param name The symbol to be retrieved.
         * @return A valid function pointer in case of success, `nullptr` otherwise.
         */
        template<typename F>
        F *sym(std::string name)
        {
            static_assert(std::is_function_v<F>);
            F *func;
            auto err = uv_dlsym(get(), name.data(), reinterpret_cast<void **>(&func));
            if (err)
            {
                func = nullptr;
            }
            return func;
        }

        /**
         * @brief Returns the last error message, if any.
         * @return The last error message, if any.
         */
        const char *error() const noexcept
        {
            return uv_dlerror(get());
        }

      private:
        bool opened;
    };

} // namespace uvw

/*-- #include "uvw/lib.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/
/*-- #include "uvw/pipe.hpp" start --*/

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/stream.hpp" start --*/

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief ConnectEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct ConnectEvent
    {
    };

    /**
     * @brief EndEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct EndEvent
    {
    };

    /**
     * @brief ListenEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct ListenEvent
    {
    };

    /**
     * @brief ShutdownEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct ShutdownEvent
    {
    };

    /**
     * @brief WriteEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct WriteEvent
    {
    };

    /**
     * @brief DataEvent event.
     *
     * It will be emitted by StreamHandle according with its functionalities.
     */
    struct DataEvent
    {
        explicit DataEvent(std::unique_ptr<char[]> buf, std::size_t len) noexcept : data{ std::move(buf) }, length{ len }
        {
        }

        std::unique_ptr<char[]> data; /*!< A bunch of data read on the stream. */
        std::size_t length;           /*!< The amount of data read on the stream. */
    };

    namespace details
    {

        struct ConnectReq final : public Request<ConnectReq, uv_connect_t>
        {
            using Request::Request;

            template<typename F, typename... Args>
            void connect(F &&f, Args &&... args)
            {
                invoke(std::forward<F>(f), get(), std::forward<Args>(args)..., &defaultCallback<ConnectEvent>);
            }
        };

        struct ShutdownReq final : public Request<ShutdownReq, uv_shutdown_t>
        {
            using Request::Request;

            void shutdown(uv_stream_t *handle)
            {
                invoke(&uv_shutdown, get(), handle, &defaultCallback<ShutdownEvent>);
            }
        };

        class WriteReq final : public Request<WriteReq, uv_write_t>
        {
          public:
            using Deleter = void (*)(char *);

            WriteReq(ConstructorAccess ca, std::shared_ptr<Loop> loop, std::unique_ptr<char[], Deleter> dt, unsigned int len)
                : Request<WriteReq, uv_write_t>{ ca, std::move(loop) }, data{ std::move(dt) }, buf{ uv_buf_init(data.get(), len) }
            {
            }

            void write(uv_stream_t *handle)
            {
                invoke(&uv_write, get(), handle, &buf, 1, &defaultCallback<WriteEvent>);
            }

            void write(uv_stream_t *handle, uv_stream_t *send)
            {
                invoke(&uv_write2, get(), handle, &buf, 1, send, &defaultCallback<WriteEvent>);
            }

          private:
            std::unique_ptr<char[], Deleter> data;
            uv_buf_t buf;
        };

    } // namespace details

    /**
     * @brief The StreamHandle handle.
     *
     * Stream handles provide an abstraction of a duplex communication channel.
     * StreamHandle is an intermediate type, `uvw` provides three stream
     * implementations: TCPHandle, PipeHandle and TTYHandle.
     */
    template<typename T, typename U>
    class StreamHandle : public Handle<T, U>
    {
        static constexpr unsigned int DEFAULT_BACKLOG = 128;

        static void readCallback(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
        {
            T &ref = *(static_cast<T *>(handle->data));
            // data will be destroyed no matter of what the value of nread is
            std::unique_ptr<char[]> data{ buf->base };

            // nread == 0 is ignored (see http://docs.libuv.org/en/v1.x/stream.html)
            // equivalent to EAGAIN/EWOULDBLOCK, it shouldn't be treated as an error
            // for we don't have data to emit though, it's fine to suppress it

            if (nread == UV_EOF)
            {
                // end of stream
                ref.publish(EndEvent{});
            }
            else if (nread > 0)
            {
                // data available
                ref.publish(DataEvent{ std::move(data), static_cast<std::size_t>(nread) });
            }
            else if (nread < 0)
            {
                // transmission error
                ref.publish(ErrorEvent(nread));
            }
        }

        static void listenCallback(uv_stream_t *handle, int status)
        {
            T &ref = *(static_cast<T *>(handle->data));
            if (status)
            {
                ref.publish(ErrorEvent{ status });
            }
            else
            {
                ref.publish(ListenEvent{});
            }
        }

      public:
#ifdef _MSC_VER
        StreamHandle(typename Handle<T, U>::ConstructorAccess ca, std::shared_ptr<Loop> ref) : Handle<T, U>{ ca, std::move(ref) }
        {
        }
#else
        using Handle<T, U>::Handle;
#endif

        /**
         * @brief Shutdowns the outgoing (write) side of a duplex stream.
         *
         * It waits for pending write requests to complete. The handle should refer
         * to a initialized stream.<br/>
         * A ShutdownEvent event will be emitted after shutdown is complete.
         */
        void shutdown()
        {
            auto listener = [ptr = this->shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            auto shutdown = this->loop().template resource<details::ShutdownReq>();
            shutdown->template once<ErrorEvent>(listener);
            shutdown->template once<ShutdownEvent>(listener);
            shutdown->shutdown(this->template get<uv_stream_t>());
        }

        /**
         * @brief Starts listening for incoming connections.
         *
         * When a new incoming connection is received, a ListenEvent event is
         * emitted.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param backlog Indicates the number of connections the kernel might
         * queue, same as listen(2).
         */
        void listen(int backlog = DEFAULT_BACKLOG)
        {
            this->invoke(&uv_listen, this->template get<uv_stream_t>(), backlog, &listenCallback);
        }

        /**
         * @brief Accepts incoming connections.
         *
         * This call is used in conjunction with `listen()` to accept incoming
         * connections. Call this function after receiving a ListenEvent event to
         * accept the connection. Before calling this function, the submitted handle
         * must be initialized.<br>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * When the ListenEvent event is emitted it is guaranteed that this
         * function will complete successfully the first time. If you attempt to use
         * it more than once, it may fail.<br/>
         * It is suggested to only call this function once per ListenEvent event.
         *
         * @note
         * Both the handles must be running on the same loop.
         *
         * @param ref An initialized handle to be used to accept the connection.
         */
        template<typename S>
        void accept(S &ref)
        {
            this->invoke(&uv_accept, this->template get<uv_stream_t>(), this->template get<uv_stream_t>(ref));
        }

        /**
         * @brief Starts reading data from an incoming stream.
         *
         * A DataEvent event will be emitted several times until there is no more
         * data to read or `stop()` is called.<br/>
         * An EndEvent event will be emitted when there is no more data to read.
         */
        void read()
        {
            this->invoke(&uv_read_start, this->template get<uv_stream_t>(), &this->allocCallback, &readCallback);
        }

        /**
         * @brief Stops reading data from the stream.
         *
         * This function is idempotent and may be safely called on a stopped stream.
         */
        void stop()
        {
            this->invoke(&uv_read_stop, this->template get<uv_stream_t>());
        }

        /**
         * @brief Writes data to the stream.
         *
         * Data are written in order. The handle takes the ownership of the data and
         * it is in charge of delete them.
         *
         * A WriteEvent event will be emitted when the data have been written.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         */
        void write(std::unique_ptr<char[]> data, unsigned int len)
        {
            auto req = this->loop().template resource<details::WriteReq>(std::unique_ptr<char[], details::WriteReq::Deleter>{ data.release(),
                                                                                                                              [](char *ptr) {
                                                                                                                                  delete[] ptr;
                                                                                                                              } },
                                                                         len);

            auto listener = [ptr = this->shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->template once<ErrorEvent>(listener);
            req->template once<WriteEvent>(listener);
            req->write(this->template get<uv_stream_t>());
        }

        /**
         * @brief Writes data to the stream.
         *
         * Data are written in order. The handle doesn't take the ownership of the
         * data. Be sure that their lifetime overcome the one of the request.
         *
         * A WriteEvent event will be emitted when the data have been written.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         */
        void write(char *data, unsigned int len)
        {
            auto req = this->loop().template resource<details::WriteReq>(std::unique_ptr<char[], details::WriteReq::Deleter>{ data,
                                                                                                                              [](char *) {
                                                                                                                              } },
                                                                         len);

            auto listener = [ptr = this->shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->template once<ErrorEvent>(listener);
            req->template once<WriteEvent>(listener);
            req->write(this->template get<uv_stream_t>());
        }

        /**
         * @brief Extended write function for sending handles over a pipe handle.
         *
         * The pipe must be initialized with `ipc == true`.
         *
         * `send` must be a TCPHandle or PipeHandle handle, which is a server or a
         * connection (listening or connected state). Bound sockets or pipes will be
         * assumed to be servers.
         *
         * The handle takes the ownership of the data and it is in charge of delete
         * them.
         *
         * A WriteEvent event will be emitted when the data have been written.<br/>
         * An ErrorEvent wvent will be emitted in case of errors.
         *
         * @param send The handle over which to write data.
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         */
        template<typename S>
        void write(S &send, std::unique_ptr<char[]> data, unsigned int len)
        {
            auto req = this->loop().template resource<details::WriteReq>(std::unique_ptr<char[], details::WriteReq::Deleter>{ data.release(),
                                                                                                                              [](char *ptr) {
                                                                                                                                  delete[] ptr;
                                                                                                                              } },
                                                                         len);

            auto listener = [ptr = this->shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->template once<ErrorEvent>(listener);
            req->template once<WriteEvent>(listener);
            req->write(this->template get<uv_stream_t>(), this->template get<uv_stream_t>(send));
        }

        /**
         * @brief Extended write function for sending handles over a pipe handle.
         *
         * The pipe must be initialized with `ipc == true`.
         *
         * `send` must be a TCPHandle or PipeHandle handle, which is a server or a
         * connection (listening or connected state). Bound sockets or pipes will be
         * assumed to be servers.
         *
         * The handle doesn't take the ownership of the data. Be sure that their
         * lifetime overcome the one of the request.
         *
         * A WriteEvent event will be emitted when the data have been written.<br/>
         * An ErrorEvent wvent will be emitted in case of errors.
         *
         * @param send The handle over which to write data.
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         */
        template<typename S>
        void write(S &send, char *data, unsigned int len)
        {
            auto req = this->loop().template resource<details::WriteReq>(std::unique_ptr<char[], details::WriteReq::Deleter>{ data,
                                                                                                                              [](char *) {
                                                                                                                              } },
                                                                         len);

            auto listener = [ptr = this->shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->template once<ErrorEvent>(listener);
            req->template once<WriteEvent>(listener);
            req->write(this->template get<uv_stream_t>(), this->template get<uv_stream_t>(send));
        }

        /**
         * @brief Queues a write request if it can be completed immediately.
         *
         * Same as `write()`, but won’t queue a write request if it can’t be
         * completed immediately.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        int tryWrite(std::unique_ptr<char[]> data, unsigned int len)
        {
            uv_buf_t bufs[] = { uv_buf_init(data.get(), len) };
            auto bw = uv_try_write(this->template get<uv_stream_t>(), bufs, 1);

            if (bw < 0)
            {
                this->publish(ErrorEvent{ bw });
                bw = 0;
            }

            return bw;
        }

        /**
         * @brief Queues a write request if it can be completed immediately.
         *
         * Same as `write()`, but won’t queue a write request if it can’t be
         * completed immediately.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param data The data to be written to the stream.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        int tryWrite(char *data, unsigned int len)
        {
            uv_buf_t bufs[] = { uv_buf_init(data, len) };
            auto bw = uv_try_write(this->template get<uv_stream_t>(), bufs, 1);

            if (bw < 0)
            {
                this->publish(ErrorEvent{ bw });
                bw = 0;
            }

            return bw;
        }

        /**
         * @brief Checks if the stream is readable.
         * @return True if the stream is readable, false otherwise.
         */
        bool readable() const noexcept
        {
            return (uv_is_readable(this->template get<uv_stream_t>()) == 1);
        }

        /**
         * @brief Checks if the stream is writable.
         * @return True if the stream is writable, false otherwise.
         */
        bool writable() const noexcept
        {
            return (uv_is_writable(this->template get<uv_stream_t>()) == 1);
        }

        /**
         * @brief Enables or disables blocking mode for a stream.
         *
         * When blocking mode is enabled all writes complete synchronously. The
         * interface remains unchanged otherwise, e.g. completion or failure of the
         * operation will still be reported through events which are emitted
         * asynchronously.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/stream.html#c.uv_stream_set_blocking)
         * for further details.
         *
         * @param enable True to enable blocking mode, false otherwise.
         * @return True in case of success, false otherwise.
         */
        bool blocking(bool enable = false)
        {
            return (0 == uv_stream_set_blocking(this->template get<uv_stream_t>(), enable));
        }

        /**
         * @brief Gets the amount of queued bytes waiting to be sent.
         * @return Amount of queued bytes waiting to be sent.
         */
        size_t writeQueueSize() const noexcept
        {
            return uv_stream_get_write_queue_size(this->template get<uv_stream_t>());
        }
    };

} // namespace uvw

/*-- #include "uvw/stream.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVChmodFlags : std::underlying_type_t<uv_poll_event>
        {
            READABLE = UV_READABLE,
            WRITABLE = UV_WRITABLE
        };

    }

    /**
     * @brief The PipeHandle handle.
     *
     * Pipe handles provide an abstraction over local domain sockets on Unix and
     * named pipes on Windows.
     *
     * To create a `PipeHandle` through a `Loop`, arguments follow:
     *
     * * An optional boolean value that indicates if this pipe will be used for
     * handle passing between processes.
     */
    class PipeHandle final : public StreamHandle<PipeHandle, uv_pipe_t>
    {
      public:
        using Chmod = details::UVChmodFlags;

        explicit PipeHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, bool pass = false) : StreamHandle{ ca, std::move(ref) }, ipc{ pass }
        {
        }

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_pipe_init, ipc);
        }

        /**
         * @brief Opens an existing file descriptor or HANDLE as a pipe.
         *
         * The passed file descriptor or HANDLE is not checked for its type, but
         * it’s required that it represents a valid pipe.<br/>
         * An ErrorEvent event is emitted in case of errors.
         *
         * @param file A valid file handle (either a file descriptor or a HANDLE).
         */
        void open(FileHandle file)
        {
            invoke(&uv_pipe_open, get(), file);
        }

        /**
         * @brief bind Binds the pipe to a file path (Unix) or a name (Windows).
         *
         * Paths on Unix get truncated typically between 92 and 108 bytes.<br/>
         * An ErrorEvent event is emitted in case of errors.
         *
         * @param name A valid file path.
         */
        void bind(std::string name)
        {
            invoke(&uv_pipe_bind, get(), name.data());
        }

        /**
         * @brief Connects to the Unix domain socket or the named pipe.
         *
         * Paths on Unix get truncated typically between 92 and 108 bytes.<br/>
         * A ConnectEvent event is emitted when the connection has been
         * established.<br/>
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param name A valid domain socket or named pipe.
         */
        void connect(std::string name)
        {
            auto listener = [ptr = shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            auto connect = loop().resource<details::ConnectReq>();
            connect->once<ErrorEvent>(listener);
            connect->once<ConnectEvent>(listener);
            connect->connect(&uv_pipe_connect, get(), name.data());
        }

        /**
         * @brief Gets the name of the Unix domain socket or the named pipe.
         * @return The name of the Unix domain socket or the named pipe, an empty
         * string in case of errors.
         */
        std::string sock() const noexcept
        {
            return details::tryRead(&uv_pipe_getsockname, get());
        }

        /**
         * @brief Gets the name of the Unix domain socket or the named pipe to which
         * the handle is connected.
         * @return The name of the Unix domain socket or the named pipe to which
         * the handle is connected, an empty string in case of errors.
         */
        std::string peer() const noexcept
        {
            return details::tryRead(&uv_pipe_getpeername, get());
        }

        /**
         * @brief Sets the number of pending pipe this instance can handle.
         *
         * This method can be used to set the number of pending pipe this instance
         * handles when the pipe server is waiting for connections.<br/>
         * Note that this setting applies to Windows only.
         *
         * @param count The number of accepted pending pipe.
         */
        void pending(int count) noexcept
        {
            uv_pipe_pending_instances(get(), count);
        }

        /**
         * @brief Gets the number of pending pipe this instance can handle.
         * @return The number of pending pipe this instance can handle.
         */
        int pending() noexcept
        {
            return uv_pipe_pending_count(get());
        }

        /**
         * @brief Used to receive handles over IPC pipes.
         *
         * Steps to be done:
         *
         * * Call `pending()`, if it’s greater than zero then proceed.
         * * Initialize a handle of the given type, as returned by `receive()`.
         * * Call `accept(pipe, handle)`.
         *
         * @return The type of the pending handle. Possible values are:
         *
         * * `HandleType::PIPE`
         * * `HandleType::TCP`
         * * `HandleType::UDP`
         * * `HandleType::UNKNOWN`
         */
        HandleType receive() noexcept
        {
            HandleCategory category = uv_pipe_pending_type(get());
            return Utilities::guessHandle(category);
        }

        /**
         * @brief Alters pipe permissions.
         *
         * It allows the pipe to be accessed from processes run by different users.
         *
         * Available flags are:
         *
         * * `PipeHandle::Chmod::READABLE`
         * * `PipeHandle::Chmod::WRITABLE`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/pipe.html#c.uv_pipe_chmod)
         * for further details.
         *
         * @param flags A valid set of flags.
         * @return True in case of success, false otherwise.
         */
        bool chmod(Flags<Chmod> flags) noexcept
        {
            return (0 == uv_pipe_chmod(get(), flags));
        }

      private:
        bool ipc;
    };

} // namespace uvw

/*-- #include "uvw/pipe.hpp" end --*/
/*-- #include "uvw/poll.hpp" start --*/

#include <memory>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVPollEvent : std::underlying_type_t<uv_poll_event>
        {
            READABLE = UV_READABLE,
            WRITABLE = UV_WRITABLE,
            DISCONNECT = UV_DISCONNECT,
            PRIORITIZED = UV_PRIORITIZED
        };

    }

    /**
     * @brief PollEvent event.
     *
     * It will be emitted by PollHandle according with its functionalities.
     */
    struct PollEvent
    {
        explicit PollEvent(Flags<details::UVPollEvent> events) noexcept : flags{ std::move(events) }
        {
        }

        /**
         * @brief Detected events all in one.
         *
         * Available flags are:
         *
         * * `PollHandle::Event::READABLE`
         * * `PollHandle::Event::WRITABLE`
         * * `PollHandle::Event::DISCONNECT`
         * * `PollHandle::Event::PRIORITIZED`
         */
        Flags<details::UVPollEvent> flags;
    };

    /**
     * @brief The PollHandle handle.
     *
     * Poll handles are used to watch file descriptors for readability, writability
     * and disconnection.
     *
     * To create a `PollHandle` through a `Loop`, arguments follow:
     *
     * * A descriptor that can be:
     *     * either an `int` file descriptor
     *     * or a `OSSocketHandle` socket descriptor
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/poll.html)
     * for further details.
     */
    class PollHandle final : public Handle<PollHandle, uv_poll_t>
    {
        static void startCallback(uv_poll_t *handle, int status, int events)
        {
            PollHandle &poll = *(static_cast<PollHandle *>(handle->data));
            if (status)
            {
                poll.publish(ErrorEvent{ status });
            }
            else
            {
                poll.publish(PollEvent{ static_cast<std::underlying_type_t<Event>>(events) });
            }
        }

      public:
        using Event = details::UVPollEvent;

        explicit PollHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, int desc) : Handle{ ca, std::move(ref) }, tag{ FD }, fd{ desc }
        {
        }

        explicit PollHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, OSSocketHandle sock)
            : Handle{ ca, std::move(ref) }, tag{ SOCKET }, socket{ sock }
        {
        }

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return (tag == SOCKET) ? initialize(&uv_poll_init_socket, socket) : initialize(&uv_poll_init, fd);
        }

        /**
         * @brief Starts polling the file descriptor.
         *
         * Available flags are:
         *
         * * `PollHandle::Event::READABLE`
         * * `PollHandle::Event::WRITABLE`
         * * `PollHandle::Event::DISCONNECT`
         * * `PollHandle::Event::PRIORITIZED`
         *
         * As soon as an event is detected, a PollEvent is emitted by the
         * handle.<br>
         * It could happen that ErrorEvent events are emitted while running.
         *
         * Calling more than once this method will update the flags to which the
         * caller is interested.
         *
         * @param flags The events to which the caller is interested.
         */
        void start(Flags<Event> flags)
        {
            invoke(&uv_poll_start, get(), flags, &startCallback);
        }

        /**
         * @brief Starts polling the file descriptor.
         *
         * Available flags are:
         *
         * * `PollHandle::Event::READABLE`
         * * `PollHandle::Event::WRITABLE`
         * * `PollHandle::Event::DISCONNECT`
         * * `PollHandle::Event::PRIORITIZED`
         *
         * As soon as an event is detected, a PollEvent is emitted by the
         * handle.<br>
         * It could happen that ErrorEvent events are emitted while running.
         *
         * Calling more than once this method will update the flags to which the
         * caller is interested.
         *
         * @param event The event to which the caller is interested.
         */
        void start(Event event)
        {
            start(Flags<Event>{ event });
        }

        /**
         * @brief Stops polling the file descriptor.
         */
        void stop()
        {
            invoke(&uv_poll_stop, get());
        }

      private:
        enum
        {
            FD,
            SOCKET
        } tag;
        union {
            int fd;
            OSSocketHandle::Type socket;
        };
    };

} // namespace uvw

/*-- #include "uvw/poll.hpp" end --*/
/*-- #include "uvw/prepare.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief PrepareEvent event.
     *
     * It will be emitted by PrepareHandle according with its functionalities.
     */
    struct PrepareEvent
    {
    };

    /**
     * @brief The PrepareHandle handle.
     *
     * Prepare handles will emit a PrepareEvent event once per loop iteration, right
     * before polling for I/O.
     *
     * To create a `PrepareHandle` through a `Loop`, no arguments are required.
     */
    class PrepareHandle final : public Handle<PrepareHandle, uv_prepare_t>
    {
        static void startCallback(uv_prepare_t *handle)
        {
            PrepareHandle &prepare = *(static_cast<PrepareHandle *>(handle->data));
            prepare.publish(PrepareEvent{});
        }

      public:
        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_prepare_init);
        }

        /**
         * @brief Starts the handle.
         *
         * A PrepareEvent event will be emitted once per loop iteration, right
         * before polling for I/O.
         *
         * The handle will start emitting PrepareEvent when needed.
         */
        void start()
        {
            invoke(&uv_prepare_start, get(), &startCallback);
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_prepare_stop, get());
        }
    };

} // namespace uvw

/*-- #include "uvw/prepare.hpp" end --*/
/*-- #include "uvw/process.hpp" start --*/

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <uv.h>
#include <vector>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/stream.hpp" start --*/
/*-- #include "uvw/stream.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVProcessFlags : std::underlying_type_t<uv_process_flags>
        {
            SETUID = UV_PROCESS_SETUID,
            SETGID = UV_PROCESS_SETGID,
            WINDOWS_VERBATIM_ARGUMENTS = UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS,
            DETACHED = UV_PROCESS_DETACHED,
            WINDOWS_HIDE = UV_PROCESS_WINDOWS_HIDE,
            WINDOWS_HIDE_CONSOLE = UV_PROCESS_WINDOWS_HIDE_CONSOLE,
            WINDOWS_HIDE_GUI = UV_PROCESS_WINDOWS_HIDE_GUI
        };

        enum class UVStdIOFlags : std::underlying_type_t<uv_stdio_flags>
        {
            IGNORE_STREAM = UV_IGNORE,
            CREATE_PIPE = UV_CREATE_PIPE,
            INHERIT_FD = UV_INHERIT_FD,
            INHERIT_STREAM = UV_INHERIT_STREAM,
            READABLE_PIPE = UV_READABLE_PIPE,
            WRITABLE_PIPE = UV_WRITABLE_PIPE,
            OVERLAPPED_PIPE = UV_OVERLAPPED_PIPE
        };

    } // namespace details

    /**
     * @brief ExitEvent event.
     *
     * It will be emitted by ProcessHandle according with its functionalities.
     */
    struct ExitEvent
    {
        explicit ExitEvent(int64_t code, int sig) noexcept : status{ code }, signal{ sig }
        {
        }

        int64_t status; /*!< The exit status. */
        int signal;     /*!< The signal that caused the process to terminate, if any. */
    };

    /**
     * @brief The ProcessHandle handle.
     *
     * Process handles will spawn a new process and allow the user to control it and
     * establish communication channels with it using streams.
     */
    class ProcessHandle final : public Handle<ProcessHandle, uv_process_t>
    {
        static void exitCallback(uv_process_t *handle, int64_t exitStatus, int termSignal)
        {
            ProcessHandle &process = *(static_cast<ProcessHandle *>(handle->data));
            process.publish(ExitEvent{ exitStatus, termSignal });
        }

      public:
        using Process = details::UVProcessFlags;
        using StdIO = details::UVStdIOFlags;

        ProcessHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref) : Handle{ ca, std::move(ref) }
        {
        }

        /**
         * @brief Disables inheritance for file descriptors/handles.
         *
         * Disables inheritance for file descriptors/handles that this process
         * inherited from its parent. The effect is that child processes spawned by
         * this process don’t accidentally inherit these handles.<br/>
         * It is recommended to call this function as early in your program as
         * possible, before the inherited file descriptors can be closed or
         * duplicated.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/process.html#c.uv_disable_stdio_inheritance)
         * for further details.
         */
        static void disableStdIOInheritance() noexcept
        {
            uv_disable_stdio_inheritance();
        }

        /**
         * @brief kill Sends the specified signal to the given PID.
         * @param pid A valid process id.
         * @param signum A valid signal identifier.
         * @return True in case of success, false otherwise.
         */
        static bool kill(int pid, int signum) noexcept
        {
            return (0 == uv_kill(pid, signum));
        }

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            // deferred initialization: libuv initializes process handles only when
            // uv_spawn is invoked and uvw stays true to the underlying library
            return true;
        }

        /**
         * @brief spawn Starts the process.
         *
         * If the process isn't successfully spawned, an ErrorEvent event will be
         * emitted by the handle.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/process.html)
         * for further details.
         *
         * @param file Path pointing to the program to be executed.
         * @param args Command line arguments.
         * @param env Optional environment for the new process.
         */
        void spawn(const char *file, char **args, char **env = nullptr)
        {
            uv_process_options_t po;

            po.exit_cb = &exitCallback;
            po.file = file;
            po.args = args;
            po.env = env;
            po.cwd = poCwd.empty() ? nullptr : poCwd.data();
            po.flags = poFlags;
            po.uid = poUid;
            po.gid = poGid;

            std::vector<uv_stdio_container_t> poStdio;
            poStdio.reserve(poFdStdio.size() + poStreamStdio.size());
            poStdio.insert(poStdio.begin(), poFdStdio.cbegin(), poFdStdio.cend());
            poStdio.insert(poStdio.end(), poStreamStdio.cbegin(), poStreamStdio.cend());

            po.stdio_count = static_cast<decltype(po.stdio_count)>(poStdio.size());
            po.stdio = poStdio.data();

            // fake initialization so as to have leak invoked
            // see init member function for more details
            initialize([](auto...) { return 0; });

            invoke(&uv_spawn, parent(), get(), &po);
        }

        /**
         * @brief Sends the specified signal to the internal process handle.
         * @param signum A valid signal identifier.
         */
        void kill(int signum)
        {
            invoke(&uv_process_kill, get(), signum);
        }

        /**
         * @brief Gets the PID of the spawned process.
         *
         * It’s set after calling `spawn()`.
         *
         * @return The PID of the spawned process.
         */
        int pid() noexcept
        {
            return get()->pid;
        }

        /**
         * @brief Sets the current working directory for the subprocess.
         * @param path The working directory to be used when `spawn()` is invoked.
         * @return A reference to this process handle.
         */
        ProcessHandle &cwd(std::string path) noexcept
        {
            poCwd = path;
            return *this;
        }

        /**
         * @brief Sets flags that control how `spawn()` behaves.
         *
         * Available flags are:
         *
         * * `ProcessHandle::Process::SETUID`
         * * `ProcessHandle::Process::SETGID`
         * * `ProcessHandle::Process::WINDOWS_VERBATIM_ARGUMENTS`
         * * `ProcessHandle::Process::DETACHED`
         * * `ProcessHandle::Process::WINDOWS_HIDE`
         * * `ProcessHandle::Process::WINDOWS_HIDE_CONSOLE`
         * * `ProcessHandle::Process::WINDOWS_HIDE_GUI`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/process.html#c.uv_process_flags)
         * for further details.
         *
         * @param flags A valid set of flags.
         * @return A reference to this process handle.
         */
        ProcessHandle &flags(Flags<Process> flags) noexcept
        {
            poFlags = flags;
            return *this;
        }

        /**
         * @brief Makes a `stdio` handle available to the child process.
         *
         * Available flags are:
         *
         * * `ProcessHandle::StdIO::IGNORE_STREAM`
         * * `ProcessHandle::StdIO::CREATE_PIPE`
         * * `ProcessHandle::StdIO::INHERIT_FD`
         * * `ProcessHandle::StdIO::INHERIT_STREAM`
         * * `ProcessHandle::StdIO::READABLE_PIPE`
         * * `ProcessHandle::StdIO::WRITABLE_PIPE`
         * * `ProcessHandle::StdIO::OVERLAPPED_PIPE`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/process.html#c.uv_stdio_flags)
         * for further details.
         *
         * @param stream A valid `stdio` handle.
         * @param flags A valid set of flags.
         * @return A reference to this process handle.
         */
        template<typename T, typename U>
        ProcessHandle &stdio(StreamHandle<T, U> &stream, Flags<StdIO> flags)
        {
            uv_stdio_container_t container;
            Flags<StdIO>::Type fgs = flags;
            container.flags = static_cast<uv_stdio_flags>(fgs);
            container.data.stream = get<uv_stream_t>(stream);
            poStreamStdio.push_back(std::move(container));
            return *this;
        }

        /**
         * @brief Makes a file descriptor available to the child process.
         *
         * Available flags are:
         *
         * * `ProcessHandle::StdIO::IGNORE_STREAM`
         * * `ProcessHandle::StdIO::CREATE_PIPE`
         * * `ProcessHandle::StdIO::INHERIT_FD`
         * * `ProcessHandle::StdIO::INHERIT_STREAM`
         * * `ProcessHandle::StdIO::READABLE_PIPE`
         * * `ProcessHandle::StdIO::WRITABLE_PIPE`
         * * `ProcessHandle::StdIO::OVERLAPPED_PIPE`
         *
         * Default file descriptors are:
         *     * `uvw::StdIN` for `stdin`
         *     * `uvw::StdOUT` for `stdout`
         *     * `uvw::StdERR` for `stderr`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/process.html#c.uv_stdio_flags)
         * for further details.
         *
         * @param fd A valid file descriptor.
         * @param flags A valid set of flags.
         * @return A reference to this process handle.
         */
        ProcessHandle &stdio(FileHandle fd, Flags<StdIO> flags)
        {
            auto fgs = static_cast<uv_stdio_flags>(Flags<StdIO>::Type{ flags });

            auto actual = FileHandle::Type{ fd };

            auto it = std::find_if(poFdStdio.begin(), poFdStdio.end(), [actual](auto &&container) { return container.data.fd == actual; });

            if (it == poFdStdio.cend())
            {
                uv_stdio_container_t container;
                container.flags = fgs;
                container.data.fd = actual;
                poFdStdio.push_back(std::move(container));
            }
            else
            {
                it->flags = fgs;
                it->data.fd = actual;
            }

            return *this;
        }

        /**
         * @brief Sets the child process' user id.
         * @param id A valid user id to be used.
         * @return A reference to this process handle.
         */
        ProcessHandle &uid(Uid id)
        {
            poUid = id;
            return *this;
        }

        /**
         * @brief Sets the child process' group id.
         * @param id A valid group id to be used.
         * @return A reference to this process handle.
         */
        ProcessHandle &gid(Gid id)
        {
            poGid = id;
            return *this;
        }

      private:
        std::string poCwd;
        Flags<Process> poFlags;
        std::vector<uv_stdio_container_t> poFdStdio;
        std::vector<uv_stdio_container_t> poStreamStdio;
        Uid poUid;
        Gid poGid;
    };

} // namespace uvw

/*-- #include "uvw/process.hpp" end --*/
/*-- #include "uvw/signal.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief SignalEvent event.
     *
     * It will be emitted by SignalHandle according with its functionalities.
     */
    struct SignalEvent
    {
        explicit SignalEvent(int sig) noexcept : signum{ sig }
        {
        }

        int signum; /*!< The signal being monitored by this handle. */
    };

    /**
     * @brief The SignalHandle handle.
     *
     * Signal handles implement Unix style signal handling on a per-event loop
     * bases.<br/>
     * Reception of some signals is emulated on Windows.
     *
     * To create a `SignalHandle` through a `Loop`, no arguments are required.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/signal.html)
     * for further details.
     */
    class SignalHandle final : public Handle<SignalHandle, uv_signal_t>
    {
        static void startCallback(uv_signal_t *handle, int signum)
        {
            SignalHandle &signal = *(static_cast<SignalHandle *>(handle->data));
            signal.publish(SignalEvent{ signum });
        }

      public:
        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_signal_init);
        }

        /**
         * @brief Starts the handle.
         *
         * The handle will start emitting SignalEvent when needed.
         *
         * @param signum The signal to be monitored.
         */
        void start(int signum)
        {
            invoke(&uv_signal_start, get(), &startCallback, signum);
        }

        /**
         * @brief Starts the handle.
         *
         * Same functionality as SignalHandle::start but the signal handler is reset
         * the moment the signal is received.
         *
         * @param signum
         */
        void oneShot(int signum)
        {
            invoke(&uv_signal_start_oneshot, get(), &startCallback, signum);
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_signal_stop, get());
        }

        /**
         * @brief Gets the signal being monitored.
         * @return The signal being monitored.
         */
        int signal() const noexcept
        {
            return get()->signum;
        }
    };

} // namespace uvw

/*-- #include "uvw/signal.hpp" end --*/
/*-- #include "uvw/tcp.hpp" start --*/

#include <chrono>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/stream.hpp" start --*/
/*-- #include "uvw/stream.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVTCPFlags : std::underlying_type_t<uv_tcp_flags>
        {
            IPV6ONLY = UV_TCP_IPV6ONLY
        };

    }

    /**
     * @brief The TCPHandle handle.
     *
     * TCP handles are used to represent both TCP streams and servers.<br/>
     * By default, _IPv4_ is used as a template parameter. The handle already
     * supports _IPv6_ out-of-the-box by using `uvw::IPv6`.
     *
     * To create a `TCPHandle` through a `Loop`, arguments follow:
     *
     * * An optional integer value that indicates the flags used to initialize
     * the socket.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/tcp.html#c.uv_tcp_init_ex)
     * for further details.
     */
    class TCPHandle final : public StreamHandle<TCPHandle, uv_tcp_t>
    {
      public:
        using Time = std::chrono::duration<unsigned int>;
        using Bind = details::UVTCPFlags;
        using IPv4 = uvw::IPv4;
        using IPv6 = uvw::IPv6;

        explicit TCPHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, unsigned int f = {})
            : StreamHandle{ ca, std::move(ref) }, tag{ f ? FLAGS : DEFAULT }, flags{ f }
        {
        }

        /**
         * @brief Initializes the handle. No socket is created as of yet.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return (tag == FLAGS) ? initialize(&uv_tcp_init_ex, flags) : initialize(&uv_tcp_init);
        }

        /**
         * @brief Opens an existing file descriptor or SOCKET as a TCP handle.
         *
         * The passed file descriptor or SOCKET is not checked for its type, but
         * it’s required that it represents a valid stream socket.
         *
         * @param socket A valid socket handle (either a file descriptor or a SOCKET).
         */
        void open(OSSocketHandle socket)
        {
            invoke(&uv_tcp_open, get(), socket);
        }

        /**
         * @brief Enables/Disables Nagle’s algorithm.
         * @param value True to enable it, false otherwise.
         * @return True in case of success, false otherwise.
         */
        bool noDelay(bool value = false)
        {
            return (0 == uv_tcp_nodelay(get(), value));
        }

        /**
         * @brief Enables/Disables TCP keep-alive.
         * @param enable True to enable it, false otherwise.
         * @param time Initial delay in seconds (use
         * `std::chrono::duration<unsigned int>`).
         * @return True in case of success, false otherwise.
         */
        bool keepAlive(bool enable = false, Time time = Time{ 0 })
        {
            return (0 == uv_tcp_keepalive(get(), enable, time.count()));
        }

        /**
         * @brief Enables/Disables simultaneous asynchronous accept requests.
         *
         * Enables/Disables simultaneous asynchronous accept requests that are
         * queued by the operating system when listening for new TCP
         * connections.<br/>
         * This setting is used to tune a TCP server for the desired performance.
         * Having simultaneous accepts can significantly improve the rate of
         * accepting connections (which is why it is enabled by default) but may
         * lead to uneven load distribution in multi-process setups.
         *
         * @param enable True to enable it, false otherwise.
         * @return True in case of success, false otherwise.
         */
        bool simultaneousAccepts(bool enable = true)
        {
            return (0 == uv_tcp_simultaneous_accepts(get(), enable));
        }

        /**
         * @brief Binds the handle to an address and port.
         *
         * A successful call to this function does not guarantee that the call to
         * `listen()` or `connect()` will work properly.<br/>
         * ErrorEvent events can be emitted because of either this function or the
         * ones mentioned above.
         *
         * Available flags are:
         *
         * * `TCPHandle::Bind::IPV6ONLY`: it disables dual-stack support and only
         * IPv6 is used.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param opts Optional additional flags.
         */
        void bind(const sockaddr &addr, Flags<Bind> opts = Flags<Bind>{})
        {
            invoke(&uv_tcp_bind, get(), &addr, opts);
        }

        /**
         * @brief Binds the handle to an address and port.
         *
         * A successful call to this function does not guarantee that the call to
         * `listen()` or `connect()` will work properly.<br/>
         * ErrorEvent events can be emitted because of either this function or the
         * ones mentioned above.
         *
         * Available flags are:
         *
         * * `TCPHandle::Bind::IPV6ONLY`: it disables dual-stack support and only
         * IPv6 is used.
         *
         * @param ip The address to which to bind.
         * @param port The port to which to bind.
         * @param opts Optional additional flags.
         */
        template<typename I = IPv4>
        void bind(std::string ip, unsigned int port, Flags<Bind> opts = Flags<Bind>{})
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            bind(reinterpret_cast<const sockaddr &>(addr), std::move(opts));
        }

        /**
         * @brief Binds the handle to an address and port.
         *
         * A successful call to this function does not guarantee that the call to
         * `listen()` or `connect()` will work properly.<br/>
         * ErrorEvent events can be emitted because of either this function or the
         * ones mentioned above.
         *
         * Available flags are:
         *
         * * `TCPHandle::Bind::IPV6ONLY`: it disables dual-stack support and only
         * IPv6 is used.
         *
         * @param addr A valid instance of Addr.
         * @param opts Optional additional flags.
         */
        template<typename I = IPv4>
        void bind(Addr addr, Flags<Bind> opts = Flags<Bind>{})
        {
            bind<I>(std::move(addr.ip), addr.port, std::move(opts));
        }

        /**
         * @brief Gets the current address to which the handle is bound.
         * @return A valid instance of Addr, an empty one in case of errors.
         */
        template<typename I = IPv4>
        Addr sock() const noexcept
        {
            return details::address<I>(&uv_tcp_getsockname, get());
        }

        /**
         * @brief Gets the address of the peer connected to the handle.
         * @return A valid instance of Addr, an empty one in case of errors.
         */
        template<typename I = IPv4>
        Addr peer() const noexcept
        {
            return details::address<I>(&uv_tcp_getpeername, get());
        }

        /**
         * @brief Establishes an IPv4 or IPv6 TCP connection.
         *
         * On Windows if the addr is initialized to point to an unspecified address
         * (`0.0.0.0` or `::`) it will be changed to point to localhost. This is
         * done to match the behavior of Linux systems.
         *
         * A ConnectEvent event is emitted when the connection has been
         * established.<br/>
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         */
        void connect(const sockaddr &addr)
        {
            auto listener = [ptr = shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            auto req = loop().resource<details::ConnectReq>();
            req->once<ErrorEvent>(listener);
            req->once<ConnectEvent>(listener);
            req->connect(&uv_tcp_connect, get(), &addr);
        }

        /**
         * @brief Establishes an IPv4 or IPv6 TCP connection.
         *
         * A ConnectEvent event is emitted when the connection has been
         * established.<br/>
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param ip The address to which to bind.
         * @param port The port to which to bind.
         */
        template<typename I = IPv4>
        void connect(std::string ip, unsigned int port)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            connect(reinterpret_cast<const sockaddr &>(addr));
        }

        /**
         * @brief Establishes an IPv4 or IPv6 TCP connection.
         *
         * A ConnectEvent event is emitted when the connection has been
         * established.<br/>
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param addr A valid instance of Addr.
         */
        template<typename I = IPv4>
        void connect(Addr addr)
        {
            connect<I>(std::move(addr.ip), addr.port);
        }

        /**
         * @brief Resets a TCP connection by sending a RST packet.
         *
         * This is accomplished by setting the `SO_LINGER` socket option with a
         * linger interval of zero and then calling `close`.<br/>
         * Due to some platform inconsistencies, mixing of `shutdown` and
         * `closeReset` calls is not allowed.
         *
         * A CloseEvent event is emitted when the connection has been reset.<br/>
         * An ErrorEvent event is emitted in case of errors.
         */
        void closeReset()
        {
            invoke(&uv_tcp_close_reset, get(), &this->closeCallback);
        }

      private:
        enum
        {
            DEFAULT,
            FLAGS
        } tag;
        unsigned int flags;
    };

} // namespace uvw

/*-- #include "uvw/tcp.hpp" end --*/
/*-- #include "uvw/thread.hpp" start --*/

#include <cstddef>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/
/*-- #include "uvw/underlying_type.hpp" start --*/
/*-- #include "uvw/underlying_type.hpp" end --*/

namespace uvw
{

    namespace details
    {

        enum class UVThreadCreateFlags : std::underlying_type_t<uv_thread_create_flags>
        {
            THREAD_NO_FLAGS = UV_THREAD_NO_FLAGS,
            THREAD_HAS_STACK_SIZE = UV_THREAD_HAS_STACK_SIZE
        };

    }

    class Thread;
    class ThreadLocalStorage;
    class Once;
    class Mutex;
    class RWLock;
    class Semaphore;
    class Condition;
    class Barrier;

    /**
     * @brief The Thread wrapper.
     *
     * To create a `Thread` through a `Loop`, arguments follow:
     *
     * * A callback invoked to initialize thread execution. The type must be such
     * that it can be assigned to an `std::function<void(std::shared_ptr<void>)>`.
     * * An optional payload the type of which is `std::shared_ptr<void>`.
     */
    class Thread final : public UnderlyingType<Thread, uv_thread_t>
    {
        using InternalTask = std::function<void(std::shared_ptr<void>)>;

        static void createCallback(void *arg)
        {
            Thread &thread = *(static_cast<Thread *>(arg));
            thread.task(thread.data);
        }

      public:
        using Options = details::UVThreadCreateFlags;
        using Task = InternalTask;
        using Type = uv_thread_t;

        explicit Thread(ConstructorAccess ca, std::shared_ptr<Loop> ref, Task t, std::shared_ptr<void> d = nullptr) noexcept
            : UnderlyingType{ ca, std::move(ref) }, data{ std::move(d) }, task{ std::move(t) }
        {
        }

        /**
         * @brief Obtains the identifier of the calling thread.
         * @return The identifier of the calling thread.
         */
        static Type self() noexcept
        {
            return uv_thread_self();
        }

        /**
         * @brief Compares thread by means of their identifiers.
         * @param tl A valid instance of a thread.
         * @param tr A valid instance of a thread.
         * @return True if the two threads are the same thread, false otherwise.
         */
        static bool equal(const Thread &tl, const Thread &tr) noexcept
        {
            return !(0 == uv_thread_equal(tl.get(), tr.get()));
        }

        ~Thread() noexcept
        {
            join();
        }

        /**
         * @brief Creates a new thread.
         * @return True in case of success, false otherwise.
         */
        bool run() noexcept
        {
            return (0 == uv_thread_create(get(), &createCallback, this));
        }

        /**
         * @brief Creates a new thread.
         *
         * Available flags are:
         *
         * * `Thread::Options::THREAD_NO_FLAGS`: no flags set.
         * * `Thread::Options::THREAD_HAS_STACK_SIZE`: if set, `stack` specifies a
         * stack size for the new thread. 0 indicates that the default value should
         * be used (it behaves as if the flag was not set). Other values will be
         * rounded up to the nearest page boundary.
         *
         * @return True in case of success, false otherwise.
         */
        bool run(Flags<Options> opts, std::size_t stack = {}) noexcept
        {
            uv_thread_options_t params{ opts, stack };
            return (0 == uv_thread_create_ex(get(), &params, &createCallback, this));
        }

        /**
         * @brief Joins with a terminated thread.
         * @return True in case of success, false otherwise.
         */
        bool join() noexcept
        {
            return (0 == uv_thread_join(get()));
        }

      private:
        std::shared_ptr<void> data;
        Task task;
    };

    /**
     * @brief The ThreadLocalStorage wrapper.
     *
     * A storage area that can only be accessed by one thread. The variable can be
     * seen as a global variable that is only visible to a particular thread and not
     * the whole program.
     */
    class ThreadLocalStorage final : public UnderlyingType<ThreadLocalStorage, uv_key_t>
    {
      public:
        explicit ThreadLocalStorage(ConstructorAccess ca, std::shared_ptr<Loop> ref) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            uv_key_create(UnderlyingType::get());
        }

        ~ThreadLocalStorage() noexcept
        {
            uv_key_delete(UnderlyingType::get());
        }

        /**
         * @brief Gets the value of a given variable.
         * @tparam T Type to which to cast the opaque storage area.
         * @return A pointer to the given variable.
         */
        template<typename T>
        T *get() noexcept
        {
            return static_cast<T *>(uv_key_get(UnderlyingType::get()));
        }

        /**
         * @brief Sets the value of a given variable.
         * @tparam T Type of the variable to store aside.
         * @param value A valid pointer to the variable to store
         */
        template<typename T>
        void set(T *value) noexcept
        {
            return uv_key_set(UnderlyingType::get(), value);
        }
    };

    /**
     * @brief The Once wrapper.
     *
     * Runs a function once and only once. Concurrent calls to `once` will block all
     * callers except one (it’s unspecified which one).
     */
    class Once final : public UnderlyingType<Once, uv_once_t>
    {
        static uv_once_t *guard() noexcept
        {
            static uv_once_t once = UV_ONCE_INIT;
            return &once;
        }

      public:
        using UnderlyingType::UnderlyingType;

        /**
         * @brief Runs a function once and only once.
         *
         * The callback must be such that it's convertible to `void(*)(void)`. Free
         * functions and non-capturing lambdas are both viable solutions.
         *
         * @tparam F Type of the callback.
         * @param f A valid callback function.
         */
        template<typename F>
        static void once(F &&f) noexcept
        {
            using CallbackType = void (*)(void);
            static_assert(std::is_convertible_v<F, CallbackType>);
            CallbackType cb = f;
            uv_once(guard(), cb);
        }
    };

    /**
     * @brief The Mutex wrapper.
     *
     * To create a `Mutex` through a `Loop`, arguments follow:
     *
     * * An option boolean that specifies if the mutex is a recursive one. The
     * default value is false, the mutex isn't recursive.
     */
    class Mutex final : public UnderlyingType<Mutex, uv_mutex_t>
    {
        friend class Condition;

      public:
        explicit Mutex(ConstructorAccess ca, std::shared_ptr<Loop> ref, bool recursive = false) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            if (recursive)
            {
                uv_mutex_init_recursive(get());
            }
            else
            {
                uv_mutex_init(get());
            }
        }

        ~Mutex() noexcept
        {
            uv_mutex_destroy(get());
        }

        /**
         * @brief Locks the mutex.
         */
        void lock() noexcept
        {
            uv_mutex_lock(get());
        }

        /**
         * @brief Tries to lock the mutex.
         * @return True in case of success, false otherwise.
         */
        bool tryLock() noexcept
        {
            return (0 == uv_mutex_trylock(get()));
        }

        /**
         * @brief Unlocks the mutex.
         */
        void unlock() noexcept
        {
            uv_mutex_unlock(get());
        }
    };

    /**
     * @brief The RWLock wrapper.
     */
    class RWLock final : public UnderlyingType<RWLock, uv_rwlock_t>
    {
      public:
        explicit RWLock(ConstructorAccess ca, std::shared_ptr<Loop> ref) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            uv_rwlock_init(get());
        }

        ~RWLock() noexcept
        {
            uv_rwlock_destroy(get());
        }

        /**
         * @brief Locks a read-write lock object for reading.
         */
        void rdLock() noexcept
        {
            uv_rwlock_rdlock(get());
        }

        /**
         * @brief Tries to lock a read-write lock object for reading.
         * @return True in case of success, false otherwise.
         */
        bool tryRdLock() noexcept
        {
            return (0 == uv_rwlock_tryrdlock(get()));
        }

        /**
         * @brief Unlocks a read-write lock object previously locked for reading.
         */
        void rdUnlock() noexcept
        {
            uv_rwlock_rdunlock(get());
        }

        /**
         * @brief Locks a read-write lock object for writing.
         */
        void wrLock() noexcept
        {
            uv_rwlock_wrlock(get());
        }

        /**
         * @brief Tries to lock a read-write lock object for writing.
         * @return True in case of success, false otherwise.
         */
        bool tryWrLock() noexcept
        {
            return (0 == uv_rwlock_trywrlock(get()));
        }

        /**
         * @brief Unlocks a read-write lock object previously locked for writing.
         */
        void wrUnlock() noexcept
        {
            uv_rwlock_wrunlock(get());
        }
    };

    /**
     * @brief The Semaphore wrapper.
     *
     * To create a `Semaphore` through a `Loop`, arguments follow:
     *
     * * An unsigned integer that specifies the initial value for the semaphore.
     */
    class Semaphore final : public UnderlyingType<Semaphore, uv_sem_t>
    {
      public:
        explicit Semaphore(ConstructorAccess ca, std::shared_ptr<Loop> ref, unsigned int value) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            uv_sem_init(get(), value);
        }

        ~Semaphore() noexcept
        {
            uv_sem_destroy(get());
        }

        /**
         * @brief Unlocks a semaphore.
         */
        void post() noexcept
        {
            uv_sem_post(get());
        }

        /**
         * @brief Locks a semaphore.
         */
        void wait() noexcept
        {
            uv_sem_wait(get());
        }

        /**
         * @brief Tries to lock a semaphore.
         * @return True in case of success, false otherwise.
         */
        bool tryWait() noexcept
        {
            return (0 == uv_sem_trywait(get()));
        }
    };

    /**
     * @brief The Condition wrapper.
     */
    class Condition final : public UnderlyingType<Condition, uv_cond_t>
    {
      public:
        explicit Condition(ConstructorAccess ca, std::shared_ptr<Loop> ref) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            uv_cond_init(get());
        }

        ~Condition() noexcept
        {
            uv_cond_destroy(get());
        }

        /**
         * @brief Signals a condition.
         *
         * This function shall unblock at least one of the threads that are blocked
         * on the specified condition variable (if any threads are blocked on it).
         */
        void signal() noexcept
        {
            uv_cond_signal(get());
        }

        /**
         * @brief Broadcasts a condition.
         *
         * This function shall unblock threads blocked on a condition variable.
         */
        void broadcast() noexcept
        {
            uv_cond_broadcast(get());
        }

        /**
         * @brief Waits on a condition.
         *
         * These function atomically releases the mutex and causes the calling
         * thread to block on the condition variable.
         *
         * @param mutex A mutex locked by the calling thread, otherwise expect
         * undefined behavior.
         */
        void wait(Mutex &mutex) noexcept
        {
            uv_cond_wait(get(), mutex.get());
        }

        /**
         * @brief Waits on a condition.
         *
         * These function atomically releases the mutex and causes the calling
         * thread to block on the condition variable.<br/>
         * The functions returns with an error if the absolute time specified passes
         * (that is, system time equals or exceeds it) before the condition is
         * signaled or broadcasted, or if the absolute time specified has already
         * been passed at the time of the call.
         *
         * @param mutex A mutex locked by the calling thread, otherwise expect
         * undefined behavior.
         * @param timeout The maximum time to wait before to return.
         * @return True in case of success, false otherwise.
         */
        bool timedWait(Mutex &mutex, uint64_t timeout) noexcept
        {
            return (0 == uv_cond_timedwait(get(), mutex.get(), timeout));
        }
    };

    /**
     * @brief The Barrier wrapper.
     *
     * To create a `Barrier` through a `Loop`, arguments follow:
     *
     * * An unsigned integer that specifies the number of threads that must call
     * `wait` before any of them successfully return from the call. The value
     * specified must be greater than zero.
     */
    class Barrier final : public UnderlyingType<Barrier, uv_barrier_t>
    {
      public:
        explicit Barrier(ConstructorAccess ca, std::shared_ptr<Loop> ref, unsigned int count) noexcept : UnderlyingType{ ca, std::move(ref) }
        {
            uv_barrier_init(get(), count);
        }

        ~Barrier() noexcept
        {
            uv_barrier_destroy(get());
        }

        /**
         * @brief Synchronizes at a barrier.
         * @return True in case of success, false otherwise.
         */
        bool wait() noexcept
        {
            return (0 == uv_barrier_wait(get()));
        }
    };

} // namespace uvw

/*-- #include "uvw/thread.hpp" end --*/
/*-- #include "uvw/timer.hpp" start --*/

#include <chrono>
#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief TimerEvent event.
     *
     * It will be emitted by TimerHandle according with its functionalities.
     */
    struct TimerEvent
    {
    };

    /**
     * @brief The TimerHandle handle.
     *
     * Timer handles are used to schedule events to be emitted in the future.
     *
     * To create a `TimerHandle` through a `Loop`, no arguments are required.
     */
    class TimerHandle final : public Handle<TimerHandle, uv_timer_t>
    {
        static void startCallback(uv_timer_t *handle)
        {
            TimerHandle &timer = *(static_cast<TimerHandle *>(handle->data));
            timer.publish(TimerEvent{});
        }

      public:
        using Time = std::chrono::duration<uint64_t, std::milli>;

        using Handle::Handle;

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_timer_init);
        }

        /**
         * @brief Starts the timer.
         *
         * If timeout is zero, a TimerEvent event is emitted on the next event loop
         * iteration. If repeat is non-zero, a TimerEvent event is emitted first
         * after timeout milliseconds and then repeatedly after repeat milliseconds.
         *
         * @param timeout Milliseconds before to emit an event (use
         * `std::chrono::duration<uint64_t, std::milli>`).
         * @param repeat Milliseconds between successive events (use
         * `std::chrono::duration<uint64_t, std::milli>`).
         */
        void start(Time timeout, Time repeat)
        {
            invoke(&uv_timer_start, get(), &startCallback, timeout.count(), repeat.count());
        }

        /**
         * @brief Stops the handle.
         */
        void stop()
        {
            invoke(&uv_timer_stop, get());
        }

        /**
         * @brief Stops the timer and restarts it if it was repeating.
         *
         * Stop the timer, and if it is repeating restart it using the repeat value
         * as the timeout.<br/>
         * If the timer has never been started before it emits an ErrorEvent event.
         */
        void again()
        {
            invoke(&uv_timer_again, get());
        }

        /**
         * @brief Sets the repeat interval value.
         *
         * The timer will be scheduled to run on the given interval and will follow
         * normal timer semantics in the case of a time-slice overrun.<br/>
         * For example, if a 50ms repeating timer first runs for 17ms, it will be
         * scheduled to run again 33ms later. If other tasks consume more than the
         * 33ms following the first timer event, then another event will be emitted
         * as soon as possible.
         *
         *  If the repeat value is set from a listener bound to an event, it does
         * not immediately take effect. If the timer was non-repeating before, it
         * will have been stopped. If it was repeating, then the old repeat value
         * will have been used to schedule the next timeout.
         *
         * @param repeat Repeat interval in milliseconds (use
         * `std::chrono::duration<uint64_t, std::milli>`).
         */
        void repeat(Time repeat)
        {
            uv_timer_set_repeat(get(), repeat.count());
        }

        /**
         * @brief Gets the timer repeat value.
         * @return Timer repeat value in milliseconds (as a
         * `std::chrono::duration<uint64_t, std::milli>`).
         */
        Time repeat()
        {
            return Time{ uv_timer_get_repeat(get()) };
        }
    };

} // namespace uvw

/*-- #include "uvw/timer.hpp" end --*/
/*-- #include "uvw/tty.hpp" start --*/

#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/stream.hpp" start --*/
/*-- #include "uvw/stream.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    namespace details
    {

        struct ResetModeMemo
        {
            ~ResetModeMemo()
            {
                uv_tty_reset_mode();
            }
        };

        enum class UVTTYModeT : std::underlying_type_t<uv_tty_mode_t>
        {
            NORMAL = UV_TTY_MODE_NORMAL,
            RAW = UV_TTY_MODE_RAW,
            IO = UV_TTY_MODE_IO
        };

        enum class UVTTYVTermStateT : std::underlying_type_t<uv_tty_vtermstate_t>
        {
            SUPPORTED = UV_TTY_SUPPORTED,
            UNSUPPORTED = UV_TTY_UNSUPPORTED
        };

    } // namespace details

    /**
     * @brief The TTYHandle handle.
     *
     * TTY handles represent a stream for the console.
     *
     * To create a `TTYHandle` through a `Loop`, arguments follow:
     *
     * * A valid FileHandle. Usually the file descriptor will be:
     *     * `uvw::StdIN` or `0` for `stdin`
     *     * `uvw::StdOUT` or `1` for `stdout`
     *     * `uvw::StdERR` or `2` for `stderr`
     * * A boolean value that specifies the plan on calling `read()` with this
     * stream. Remember that `stdin` is readable, `stdout` is not.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/tty.html#c.uv_tty_init)
     * for further details.
     */
    class TTYHandle final : public StreamHandle<TTYHandle, uv_tty_t>
    {
        static auto resetModeMemo()
        {
            static std::weak_ptr<details::ResetModeMemo> weak;
            auto shared = weak.lock();
            if (!shared)
            {
                weak = shared = std::make_shared<details::ResetModeMemo>();
            }
            return shared;
        }

      public:
        using Mode = details::UVTTYModeT;
        using VTermState = details::UVTTYVTermStateT;

        explicit TTYHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, FileHandle desc, bool readable)
            : StreamHandle{ ca, std::move(ref) }, memo{ resetModeMemo() }, fd{ desc }, rw{ readable }
        {
        }

        /**
         * @brief Initializes the handle.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return initialize(&uv_tty_init, fd, rw);
        }

        /**
         * @brief Sets the TTY using the specified terminal mode.
         *
         * Available modes are:
         *
         * * `TTY::Mode::NORMAL`
         * * `TTY::Mode::RAW`
         * * `TTY::Mode::IO`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/tty.html#c.uv_tty_mode_t)
         * for further details.
         *
         * @param m The mode to be set.
         * @return True in case of success, false otherwise.
         */
        bool mode(Mode m)
        {
            return (0 == uv_tty_set_mode(get(), static_cast<std::underlying_type_t<Mode>>(m)));
        }

        /**
         * @brief Resets TTY settings to default values.
         * @return True in case of success, false otherwise.
         */
        bool reset() noexcept
        {
            return (0 == uv_tty_reset_mode());
        }

        /**
         * @brief Gets the current Window size.
         * @return The current Window size or `{-1, -1}` in case of errors.
         */
        WinSize getWinSize()
        {
            WinSize size;

            if (0 != uv_tty_get_winsize(get(), &size.width, &size.height))
            {
                size.width = -1;
                size.height = -1;
            }

            return size;
        }

        /**
         * @brief Controls whether console virtual terminal sequences are processed
         * by the library or console.
         *
         * This function is only meaningful on Windows systems. On Unix it is
         * silently ignored.
         *
         * Available states are:
         *
         * * `TTY::VTermState::SUPPORTED`
         * * `TTY::VTermState::UNSUPPORTED`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/tty.html#c.uv_tty_vtermstate_t)
         * for further details.
         *
         * @param s The state to be set.
         */
        void vtermState(VTermState s) const noexcept
        {
            switch (s)
            {
                case VTermState::SUPPORTED: uv_tty_set_vterm_state(uv_tty_vtermstate_t::UV_TTY_SUPPORTED); break;
                case VTermState::UNSUPPORTED: uv_tty_set_vterm_state(uv_tty_vtermstate_t::UV_TTY_UNSUPPORTED); break;
            }
        }

        /**
         * @brief Gets the current state of whether console virtual terminal
         * sequences are handled by the library or the console.
         *
         * This function is not implemented on Unix.
         *
         * Available states are:
         *
         * * `TTY::VTermState::SUPPORTED`
         * * `TTY::VTermState::UNSUPPORTED`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/tty.html#c.uv_tty_vtermstate_t)
         * for further details.
         *
         * @return The current state.
         */
        VTermState vtermState() const noexcept
        {
            uv_tty_vtermstate_t state;
            uv_tty_get_vterm_state(&state);
            return VTermState{ state };
        }

      private:
        std::shared_ptr<details::ResetModeMemo> memo;
        FileHandle::Type fd;
        int rw;
    };

} // namespace uvw

/*-- #include "uvw/tty.hpp" end --*/
/*-- #include "uvw/udp.hpp" start --*/

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/handle.hpp" start --*/
/*-- #include "uvw/handle.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/

namespace uvw
{

    /**
     * @brief SendEvent event.
     *
     * It will be emitted by UDPHandle according with its functionalities.
     */
    struct SendEvent
    {
    };

    /**
     * @brief UDPDataEvent event.
     *
     * It will be emitted by UDPHandle according with its functionalities.
     */
    struct UDPDataEvent
    {
        explicit UDPDataEvent(Addr sndr, std::unique_ptr<char[]> buf, std::size_t len, bool part) noexcept
            : data{ std::move(buf) }, length{ len }, sender{ std::move(sndr) }, partial{ part }
        {
        }

        std::unique_ptr<char[]> data; /*!< A bunch of data read on the stream. */
        std::size_t length;                 /*!< The amount of data read on the stream. */
        Addr sender;                        /*!< A valid instance of Addr. */
        bool partial;                       /*!< True if the message was truncated, false otherwise. */
    };

    namespace details
    {

        enum class UVUDPFlags : std::underlying_type_t<uv_udp_flags>
        {
            IPV6ONLY = UV_UDP_IPV6ONLY,
            REUSEADDR = UV_UDP_REUSEADDR
        };

        enum class UVMembership : std::underlying_type_t<uv_membership>
        {
            LEAVE_GROUP = UV_LEAVE_GROUP,
            JOIN_GROUP = UV_JOIN_GROUP
        };

        class SendReq final : public Request<SendReq, uv_udp_send_t>
        {
          public:
            using Deleter = void (*)(char *);

            SendReq(ConstructorAccess ca, std::shared_ptr<Loop> loop, std::unique_ptr<char[], Deleter> dt, unsigned int len)
                : Request<SendReq, uv_udp_send_t>{ ca, std::move(loop) }, data{ std::move(dt) }, buf{ uv_buf_init(data.get(), len) }
            {
            }

            void send(uv_udp_t *handle, const struct sockaddr *addr)
            {
                invoke(&uv_udp_send, get(), handle, &buf, 1, addr, &defaultCallback<SendEvent>);
            }

          private:
            std::unique_ptr<char[], Deleter> data;
            uv_buf_t buf;
        };

    } // namespace details

    /**
     * @brief The UDPHandle handle.
     *
     * UDP handles encapsulate UDP communication for both clients and servers.<br/>
     * By default, _IPv4_ is used as a template parameter. The handle already
     * supports _IPv6_ out-of-the-box by using `uvw::IPv6`.
     *
     * To create an `UDPHandle` through a `Loop`, arguments follow:
     *
     * * An optional integer value that indicates optional flags used to initialize
     * the socket.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_init_ex)
     * for further details.
     */
    class UDPHandle final : public Handle<UDPHandle, uv_udp_t>
    {
        template<typename I>
        static void recvCallback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, unsigned flags)
        {
            const typename details::IpTraits<I>::Type *aptr = reinterpret_cast<const typename details::IpTraits<I>::Type *>(addr);

            UDPHandle &udp = *(static_cast<UDPHandle *>(handle->data));
            // data will be destroyed no matter of what the value of nread is
            std::unique_ptr<char[]> data{ buf->base };

            if (nread > 0)
            {
                // data available (can be truncated)
                udp.publish(UDPDataEvent{ details::address<I>(aptr), std::move(data), static_cast<std::size_t>(nread),
                                          !(0 == (flags & UV_UDP_PARTIAL)) });
            }
            else if (nread == 0 && addr == nullptr)
            {
                // no more data to be read, doing nothing is fine
            }
            else if (nread == 0 && addr != nullptr)
            {
                // empty udp packet
                udp.publish(UDPDataEvent{ details::address<I>(aptr), std::move(data), static_cast<std::size_t>(nread), false });
            }
            else
            {
                // transmission error
                udp.publish(ErrorEvent(nread));
            }
        }

      public:
        using Membership = details::UVMembership;
        using Bind = details::UVUDPFlags;
        using IPv4 = uvw::IPv4;
        using IPv6 = uvw::IPv6;

        using Handle::Handle;

        explicit UDPHandle(ConstructorAccess ca, std::shared_ptr<Loop> ref, unsigned int f)
            : Handle{ ca, std::move(ref) }, tag{ FLAGS }, flags{ f }
        {
        }

        /**
         * @brief Initializes the handle. The actual socket is created lazily.
         * @return True in case of success, false otherwise.
         */
        bool init()
        {
            return (tag == FLAGS) ? initialize(&uv_udp_init_ex, flags) : initialize(&uv_udp_init);
        }

        /**
         * @brief Opens an existing file descriptor or SOCKET as a UDP handle.
         *
         * The passed file descriptor or SOCKET is not checked for its type, but
         * it’s required that it represents a valid datagram socket.
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_open)
         * for further details.
         *
         * @param socket A valid socket handle (either a file descriptor or a SOCKET).
         */
        void open(OSSocketHandle socket)
        {
            invoke(&uv_udp_open, get(), socket);
        }

        /**
         * @brief Binds the UDP handle to an IP address and port.
         *
         * Available flags are:
         *
         * * `UDPHandle::Bind::IPV6ONLY`
         * * `UDPHandle::Bind::REUSEADDR`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_flags)
         * for further details.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param opts Optional additional flags.
         */
        void bind(const sockaddr &addr, Flags<Bind> opts = Flags<Bind>{})
        {
            invoke(&uv_udp_bind, get(), &addr, opts);
        }

        /**
         * @brief Associates the handle to a remote address and port (either IPv4 or
         * IPv6).
         *
         * Every message sent by this handle is automatically sent to the given
         * destination.<br/>
         * Trying to call this function on an already connected handle isn't
         * allowed.
         *
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         */
        void connect(const sockaddr &addr)
        {
            invoke(&uv_udp_connect, get(), &addr);
        }

        /**
         * @brief Associates the handle to a remote address and port (either IPv4 or
         * IPv6).
         *
         * Every message sent by this handle is automatically sent to the given
         * destination.<br/>
         * Trying to call this function on an already connected handle isn't
         * allowed.
         *
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param ip The address to which to bind.
         * @param port The port to which to bind.
         */
        template<typename I = IPv4>
        void connect(std::string ip, unsigned int port)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            connect(reinterpret_cast<const sockaddr &>(addr));
        }

        /**
         * @brief Associates the handle to a remote address and port (either IPv4 or
         * IPv6).
         *
         * Every message sent by this handle is automatically sent to the given
         * destination.<br/>
         * Trying to call this function on an already connected handle isn't
         * allowed.
         *
         * An ErrorEvent event is emitted in case of errors during the connection.
         *
         * @param addr A valid instance of Addr.
         */
        template<typename I = IPv4>
        void connect(Addr addr)
        {
            connect<I>(std::move(addr.ip), addr.port);
        }

        /**
         * @brief Disconnects the handle.
         *
         * Trying to disconnect a handle that is not connected isn't allowed.
         *
         * An ErrorEvent event is emitted in case of errors.
         */
        void disconnect()
        {
            invoke(&uv_udp_connect, get(), nullptr);
        }

        /**
         * @brief Gets the remote address to which the handle is connected, if any.
         * @return A valid instance of Addr, an empty one in case of errors.
         */
        template<typename I = IPv4>
        Addr peer() const noexcept
        {
            return details::address<I>(&uv_udp_getpeername, get());
        }

        /**
         * @brief Binds the UDP handle to an IP address and port.
         *
         * Available flags are:
         *
         * * `UDPHandle::Bind::IPV6ONLY`
         * * `UDPHandle::Bind::REUSEADDR`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_flags)
         * for further details.
         *
         * @param ip The IP address to which to bind.
         * @param port The port to which to bind.
         * @param opts Optional additional flags.
         */
        template<typename I = IPv4>
        void bind(std::string ip, unsigned int port, Flags<Bind> opts = Flags<Bind>{})
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            bind(reinterpret_cast<const sockaddr &>(addr), std::move(opts));
        }

        /**
         * @brief Binds the UDP handle to an IP address and port.
         *
         * Available flags are:
         *
         * * `UDPHandle::Bind::IPV6ONLY`
         * * `UDPHandle::Bind::REUSEADDR`
         *
         * See the official
         * [documentation](http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_flags)
         * for further details.
         *
         * @param addr A valid instance of Addr.
         * @param opts Optional additional flags.
         */
        template<typename I = IPv4>
        void bind(Addr addr, Flags<Bind> opts = Flags<Bind>{})
        {
            bind<I>(std::move(addr.ip), addr.port, std::move(opts));
        }

        /**
         * @brief Get the local IP and port of the UDP handle.
         * @return A valid instance of Addr, an empty one in case of errors.
         */
        template<typename I = IPv4>
        Addr sock() const noexcept
        {
            return details::address<I>(&uv_udp_getsockname, get());
        }

        /**
         * @brief Sets membership for a multicast address.
         *
         * Available values for `membership` are:
         *
         * * `UDPHandle::Membership::LEAVE_GROUP`
         * * `UDPHandle::Membership::JOIN_GROUP`
         *
         * @param multicast Multicast address to set membership for.
         * @param iface Interface address.
         * @param membership Action to be performed.
         * @return True in case of success, false otherwise.
         */
        template<typename I = IPv4>
        bool multicastMembership(std::string multicast, std::string iface, Membership membership)
        {
            return (0 == uv_udp_set_membership(get(), multicast.data(), iface.data(), static_cast<uv_membership>(membership)));
        }

        /**
         * @brief Sets IP multicast loop flag.
         *
         * This makes multicast packets loop back to local sockets.
         *
         * @param enable True to enable multicast loop, false otherwise.
         * @return True in case of success, false otherwise.
         */
        bool multicastLoop(bool enable = true)
        {
            return (0 == uv_udp_set_multicast_loop(get(), enable));
        }

        /**
         * @brief Sets the multicast ttl.
         * @param val A value in the range `[1, 255]`.
         * @return True in case of success, false otherwise.
         */
        bool multicastTtl(int val)
        {
            return (0 == uv_udp_set_multicast_ttl(get(), val > 255 ? 255 : val));
        }

        /**
         * @brief Sets the multicast interface to send or receive data on.
         * @param iface Interface address.
         * @return True in case of success, false otherwise.
         */
        template<typename I = IPv4>
        bool multicastInterface(std::string iface)
        {
            return (0 == uv_udp_set_multicast_interface(get(), iface.data()));
        }

        /**
         * @brief Sets broadcast on or off.
         * @param enable True to set broadcast on, false otherwise.
         * @return True in case of success, false otherwise.
         */
        bool broadcast(bool enable = false)
        {
            return (0 == uv_udp_set_broadcast(get(), enable));
        }

        /**
         * @brief Sets the time to live.
         * @param val A value in the range `[1, 255]`.
         * @return True in case of success, false otherwise.
         */
        bool ttl(int val)
        {
            return (0 == uv_udp_set_ttl(get(), val > 255 ? 255 : val));
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle takes the ownership of the data and it is in charge of delete
         * them.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        void send(const sockaddr &addr, std::unique_ptr<char[]> data, unsigned int len)
        {
            auto req = loop().resource<details::SendReq>(std::unique_ptr<char[], details::SendReq::Deleter>{ data.release(),
                                                                                                             [](char *ptr) {
                                                                                                                 delete[] ptr;
                                                                                                             } },
                                                         len);

            auto listener = [ptr = shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->once<ErrorEvent>(listener);
            req->once<SendEvent>(listener);
            req->send(get(), &addr);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle takes the ownership of the data and it is in charge of delete
         * them.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param ip The address to which to send data.
         * @param port The port to which to send data.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        template<typename I = IPv4>
        void send(std::string ip, unsigned int port, std::unique_ptr<char[]> data, unsigned int len)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            send(reinterpret_cast<const sockaddr &>(addr), std::move(data), len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle takes the ownership of the data and it is in charge of delete
         * them.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param addr A valid instance of Addr.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        template<typename I = IPv4>
        void send(Addr addr, std::unique_ptr<char[]> data, unsigned int len)
        {
            send<I>(std::move(addr.ip), addr.port, std::move(data), len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle doesn't take the ownership of the data. Be sure that their
         * lifetime overcome the one of the request.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        void send(const sockaddr &addr, char *data, unsigned int len)
        {
            auto req = loop().resource<details::SendReq>(std::unique_ptr<char[], details::SendReq::Deleter>{ data,
                                                                                                             [](char *) {
                                                                                                             } },
                                                         len);

            auto listener = [ptr = shared_from_this()](const auto &event, const auto &) {
                ptr->publish(event);
            };

            req->once<ErrorEvent>(listener);
            req->once<SendEvent>(listener);
            req->send(get(), &addr);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle doesn't take the ownership of the data. Be sure that their
         * lifetime overcome the one of the request.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param ip The address to which to send data.
         * @param port The port to which to send data.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        template<typename I = IPv4>
        void send(std::string ip, unsigned int port, char *data, unsigned int len)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            send(reinterpret_cast<const sockaddr &>(addr), data, len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * will be bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a
         * random port number.
         *
         * The handle doesn't take the ownership of the data. Be sure that their
         * lifetime overcome the one of the request.
         *
         * A SendEvent event will be emitted when the data have been sent.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         *
         * @param addr A valid instance of Addr.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         */
        template<typename I = IPv4>
        void send(Addr addr, char *data, unsigned int len)
        {
            send<I>(std::move(addr.ip), addr.port, data, len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(const sockaddr &addr, std::unique_ptr<char[]> data, unsigned int len)
        {
            uv_buf_t bufs[] = { uv_buf_init(data.get(), len) };
            auto bw = uv_udp_try_send(get(), bufs, 1, &addr);

            if (bw < 0)
            {
                publish(ErrorEvent{ bw });
                bw = 0;
            }

            return bw;
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param ip The address to which to send data.
         * @param port The port to which to send data.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(std::string ip, unsigned int port, std::unique_ptr<char[]> data, unsigned int len)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            return trySend(reinterpret_cast<const sockaddr &>(addr), std::move(data), len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param addr A valid instance of Addr.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(Addr addr, std::unique_ptr<char[]> data, unsigned int len)
        {
            return trySend<I>(std::move(addr.ip), addr.port, std::move(data), len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param addr Initialized `sockaddr_in` or `sockaddr_in6` data structure.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(const sockaddr &addr, char *data, unsigned int len)
        {
            uv_buf_t bufs[] = { uv_buf_init(data, len) };
            auto bw = uv_udp_try_send(get(), bufs, 1, &addr);

            if (bw < 0)
            {
                publish(ErrorEvent{ bw });
                bw = 0;
            }

            return bw;
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param ip The address to which to send data.
         * @param port The port to which to send data.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(std::string ip, unsigned int port, char *data, unsigned int len)
        {
            typename details::IpTraits<I>::Type addr;
            details::IpTraits<I>::addrFunc(ip.data(), port, &addr);
            return trySend(reinterpret_cast<const sockaddr &>(addr), data, len);
        }

        /**
         * @brief Sends data over the UDP socket.
         *
         * Same as `send()`, but it won’t queue a send request if it can’t be
         * completed immediately.
         *
         * @param addr A valid instance of Addr.
         * @param data The data to be sent.
         * @param len The lenght of the submitted data.
         * @return Number of bytes written.
         */
        template<typename I = IPv4>
        int trySend(Addr addr, char *data, unsigned int len)
        {
            return trySend<I>(std::move(addr.ip), addr.port, data, len);
        }

        /**
         * @brief Prepares for receiving data.
         *
         * Note that if the socket has not previously been bound with `bind()`, it
         * is bound to `0.0.0.0` (the _all interfaces_ IPv4 address) and a random
         * port number.
         *
         * An UDPDataEvent event will be emitted when the handle receives data.<br/>
         * An ErrorEvent event will be emitted in case of errors.
         */
        template<typename I = IPv4>
        void recv()
        {
            invoke(&uv_udp_recv_start, get(), &allocCallback, &recvCallback<I>);
        }

        /**
         * @brief Stops listening for incoming datagrams.
         */
        void stop()
        {
            invoke(&uv_udp_recv_stop, get());
        }

        /**
         * @brief Gets the number of bytes queued for sending.
         *
         * It strictly shows how much information is currently queued.
         *
         * @return Number of bytes queued for sending.
         */
        size_t sendQueueSize() const noexcept
        {
            return uv_udp_get_send_queue_size(get());
        }

        /**
         * @brief Number of send requests currently in the queue awaiting to be
         * processed.
         * @return Number of send requests currently in the queue.
         */
        size_t sendQueueCount() const noexcept
        {
            return uv_udp_get_send_queue_count(get());
        }

      private:
        enum
        {
            DEFAULT,
            FLAGS
        } tag{ DEFAULT };
        unsigned int flags{};
    };

} // namespace uvw

/*-- #include "uvw/udp.hpp" end --*/
/*-- #include "uvw/util.hpp" start --*/
/*-- #include "uvw/util.hpp" end --*/
/*-- #include "uvw/work.hpp" start --*/

#include <functional>
#include <memory>
#include <utility>
#include <uv.h>
/*-- #include "uvw/request.hpp" start --*/
/*-- #include "uvw/request.hpp" end --*/
/*-- #include "uvw/loop.hpp" start --*/
/*-- #include "uvw/loop.hpp" end --*/

namespace uvw
{

    /**
     * @brief WorkEvent event.
     *
     * It will be emitted by WorkReq according with its functionalities.
     */
    struct WorkEvent
    {
    };

    /**
     * @brief The WorkReq request.
     *
     * It runs user code using a thread from the threadpool and gets notified in the
     * loop thread by means of an event.
     *
     * To create a `WorkReq` through a `Loop`, arguments follow:
     *
     * * A valid instance of a `Task`, that is of type `std::function<void(void)>`.
     *
     * See the official
     * [documentation](http://docs.libuv.org/en/v1.x/threadpool.html)
     * for further details.
     */
    class WorkReq final : public Request<WorkReq, uv_work_t>
    {
        using InternalTask = std::function<void(void)>;

        static void workCallback(uv_work_t *req)
        {
            static_cast<WorkReq *>(req->data)->task();
        }

      public:
        using Task = InternalTask;

        explicit WorkReq(ConstructorAccess ca, std::shared_ptr<Loop> ref, InternalTask t) : Request{ ca, std::move(ref) }, task{ t }
        {
        }

        /**
         * @brief Runs the given task in a separate thread.
         *
         * A WorkEvent event will be emitted on the loop thread when the task is
         * finished.<br/>
         * This request can be cancelled with `cancel()`.
         */
        void queue()
        {
            invoke(&uv_queue_work, parent(), get(), &workCallback, &defaultCallback<WorkEvent>);
        }

      private:
        Task task{};
    };

} // namespace uvw

/*-- #include "uvw/work.hpp" end --*/

/*-- #include "uvw.hpp" end --*/
#endif
