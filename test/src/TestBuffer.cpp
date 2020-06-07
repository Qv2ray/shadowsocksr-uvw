#include <Buffer.hpp>
#include "uvw/udp.h"
#include "uvw/tcp.h"
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("newBuf", "[BufferTest]")
{
    auto buf = std::unique_ptr<buffer_t>(Buffer::newBuf());
    REQUIRE(buf->capacity == Buffer::BUF_DEFAULT_CAPACITY);
    REQUIRE(buf->len == 0);
    REQUIRE(buf->idx == 0);
}

TEST_CASE("drop", "[BufferTest]")
{
    auto buf = Buffer();
    auto begin = buf.begin();
    auto back = buf.back();
    REQUIRE(begin == back);
    char a[] { 0x05, 0x00, 0x01, 0x03 };
    buf.copyFromBegin(a, 4);
    REQUIRE(buf.length() == 4);
    REQUIRE(buf.back() == begin + 4);
    buf.drop(3);
    REQUIRE(*buf.begin() == 0x03);
    buf.drop(1);
    REQUIRE(buf.length() == 0);
    //no data to drop
    buf.drop(20);
    REQUIRE(buf.begin() == buf.back());
    REQUIRE(buf.length() == 0);
    buf.copyFromBegin(a, 4);
    REQUIRE(buf.length() == 4);
    REQUIRE(*buf.getCapacityPtr() == Buffer::BUF_DEFAULT_CAPACITY);
    buf.setLength(0);
    REQUIRE(buf.length() == 0);
}

TEST_CASE("BufRealloc", "[BufferTest]")
{
    auto buf = Buffer();
    char a[Buffer::BUF_DEFAULT_CAPACITY];
    buf.copyFromBegin(a, Buffer::BUF_DEFAULT_CAPACITY);
    buf.bufRealloc(2045);
    REQUIRE(buf.length() == 2045);
    REQUIRE(*buf.getCapacityPtr() == 2045);
}
TEST_CASE("DuplicatDataToArray", "[BufferTest]")
{
    auto buf = Buffer();
    char a[Buffer::BUF_DEFAULT_CAPACITY] { 0x05, 0x01 };
    buf.copyFromBegin(a, Buffer::BUF_DEFAULT_CAPACITY);
    auto array = buf.duplicateDataToArray();
    for (int i = 0; i < Buffer::BUF_DEFAULT_CAPACITY; ++i) {
        REQUIRE(a[i] == array[i]);
    }
}

TEST_CASE("CopyEvent", "[BufferTest]")
{
    auto array = std::make_unique<char[]>(2099);
    uvw::DataEvent event { std::move(array), 2099 };
    auto buf = Buffer();
    buf.copy(event);
    //like vector, when capacity is not enough, double capacity with data length.
    REQUIRE(*buf.getCapacityPtr() == event.length * 2);
    REQUIRE(buf.length() == 2099);
    //the capacity is enough, nothing happen.
    buf.copy(event);
    REQUIRE(*buf.getCapacityPtr() == event.length * 2);
    REQUIRE(buf.length() == 2099 * 2);
    event.length = 0;
    buf.copy(event); // no data to copy, because it's length is zero.
    REQUIRE(buf.length() == 2099 * 2);
    auto array2 = std::make_unique<char[]>(2099);
    for (int i = 0; i < 2099; ++i)
        array2[i] = i % 255;
    uvw::DataEvent event2 { std::move(array2), 2099 };
    REQUIRE(array2 == nullptr);
    buf.copyFromBegin(event2);
    REQUIRE(buf.length() == 2099); //when we copy copyFromBegin, the length is reset to event2 length.
    REQUIRE(*buf.getCapacityPtr() == event2.length * 2);
    for (int i = 0; i < 2099; ++i) {
        REQUIRE(buf[i] == event2.data[i]);
    }
}

TEST_CASE("UDPCopyEvent", "[BufferTest]")
{
    auto array = std::make_unique<char[]>(2099);
    uvw::Addr addr; //fake sender
    uvw::UDPDataEvent event { std::move(addr), std::move(array), 2099, false };
    auto buf = Buffer();
    buf.copy(event);
    //like vector, when capacity is not enough, double capacity with data length.
    REQUIRE(*buf.getCapacityPtr() == event.length * 2);
    REQUIRE(buf.length() == 2099);
    //the capacity is enough, nothing happen.
    buf.copy(event);
    REQUIRE(*buf.getCapacityPtr() == event.length * 2);
    REQUIRE(buf.length() == 2099 * 2);
    event.length = 0;
    buf.copy(event); // no data to copy, because it's length is zero.
    REQUIRE(buf.length() == 2099 * 2);
}
