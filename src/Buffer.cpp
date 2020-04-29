#include "Buffer.hpp"

#include "ConnectionContext.hpp"
#include "ObfsClass.hpp"
#include "UDPRelay.hpp"
#include "encrypt.h"
#include "ssrutils.h"
#include "uvw_single.hpp"

#include <algorithm>
namespace
{
void freeBuf(buffer_t* buf)
{
    free(buf->array);
    free(buf);
}
} // namespace
Buffer::Buffer()
    : buf { newBuf(), freeBuf }
{
}

size_t* Buffer::getLengthPtr()
{
    return &buf->len;
}

buffer_t* Buffer::newBuf()
{
    auto bufPtr = reinterpret_cast<buffer_t*>(malloc(sizeof(buffer_t)));
    balloc(bufPtr, Buffer::BUF_DEFAULT_CAPACITY);
    bufPtr->capacity = Buffer::BUF_DEFAULT_CAPACITY;
    bufPtr->len = 0;
    bufPtr->idx = 0;
    return bufPtr;
}

char Buffer::operator[](int idx)
{
    return buf->array[idx % (buf->capacity)];
}

char** Buffer::getBufPtr()
{
    return &buf->array;
}

char* Buffer::back()
{
    if (buf)
        return buf->array + buf->len;
    return nullptr;
}

char* Buffer::begin()
{
    return buf->array;
}

void Buffer::clear()
{
    buf->len = 0;
}

void Buffer::drop(size_t size)
{
    if (buf->len < size)
        return;
    memmove(buf->array, buf->array + size, buf->len - size);
    buf->len -= size;
}

void Buffer::bufRealloc(size_t size)
{
    buf->array = reinterpret_cast<char*>(realloc(buf->array, size * sizeof(char)));
    buf->capacity = size;
    buf->len = buf->capacity < buf->len ? buf->capacity : buf->len;
}

std::unique_ptr<char[]> Buffer::duplicateDataToArray()
{
    std::unique_ptr<char[]> data { new char[buf->len]() };
    memcpy(data.get(), buf->array, buf->len);
    return data;
}

void Buffer::copy(const uvw::DataEvent& event)
{
    if (event.length == 0)
        return;
    if (event.length + buf->len <= buf->capacity) {
        this->copy(event.data.get(), event.data.get() + event.length);
        return;
    } else if (buf->len < buf->capacity) {
        bufRealloc(event.length * 2);
        buf->capacity = event.length * 2;
        this->copy(event.data.get(), event.data.get() + event.length);
        return;
    }
}

void Buffer::copy(const uvw::UDPDataEvent& event)
{
    if (event.length == 0)
        return;
    if (event.length + buf->len <= buf->capacity) {
        this->copy(event.data.get(), event.data.get() + event.length);
        return;
    } else if (buf->len < buf->capacity) {
        bufRealloc(event.length * 2);
        buf->capacity = event.length * 2;
        this->copy(event.data.get(), event.data.get() + event.length);
        return;
    }
}

void Buffer::copyFromBegin(const uvw::DataEvent& event, int length)
{
    auto start = event.data.get();
    auto size = length == -1 ? event.length : length;
    memcpy(begin(), start, size);
    buf->len = size;
}

void Buffer::copyFromBegin(char* start, size_t size)
{
    memcpy(begin(), start, size);
    buf->len = size;
}

void Buffer::copy(const Buffer& that)
{
    memcpy(buf->array, that.buf->array, that.buf->len);
    buf->len = that.buf->len;
}

void Buffer::setLength(int l)
{
    buf->len = l;
}

size_t Buffer::length()
{
    return buf->len;
}

void Buffer::protocolPluginPreEncrypt(ObfsClass& obfsClass, ConnectionContext& connectionContext)
{
    if (obfsClass.protocol_plugin && obfsClass.protocol_plugin->client_pre_encrypt) {
        setLength(obfsClass.protocol_plugin->client_pre_encrypt(connectionContext.protocolPtr.get(), getBufPtr(), buf->len, &buf->capacity));
    }
}

void Buffer::protocolPluginPostDecrypt(ObfsClass& obfsClass, ConnectionContext& connectionContext)
{
    if (obfsClass.protocol_plugin && obfsClass.protocol_plugin->client_post_decrypt) {
        setLength(obfsClass.protocol_plugin->client_post_decrypt(connectionContext.protocolPtr.get(), getBufPtr(), buf->len, &buf->capacity));
    }
}

int Buffer::ssEncrypt(CipherEnv& cipherEnv, ConnectionContext& connectionContext)
{
    int err = ss_encrypt(&cipherEnv.cipher, buf.get(), connectionContext.e_ctx.get(), BUF_DEFAULT_CAPACITY);
    return err;
}

int Buffer::ssDecrypt(CipherEnv& cipherEnv, ConnectionContext& connectionContext)
{
    int err = ss_decrypt(&cipherEnv.cipher, buf.get(), connectionContext.d_ctx.get(), BUF_DEFAULT_CAPACITY);
    return err;
}

void Buffer::clientEncode(ObfsClass& obfsClass, ConnectionContext& connectionContext, int encodeLen)
{
    if (obfsClass.obfs_plugin) {
        if (obfsClass.obfs_plugin->client_encode) {
            auto encode = obfsClass.obfs_plugin->client_encode;
            setLength(encode(connectionContext.obfsPtr.get(), getBufPtr(), encodeLen == -1 ? buf->len : 0, &buf->capacity));
        }
    }
}

int Buffer::clientDecode(ObfsClass& obfsClass, ConnectionContext& connectionContext)
{
    int needSendBack = 0;
    if (obfsClass.obfs_plugin) {
        if (obfsClass.obfs_plugin->client_decode) {
            auto decode = obfsClass.obfs_plugin->client_decode;
            setLength(decode(connectionContext.obfsPtr.get(), getBufPtr(), buf->len, &buf->capacity, &needSendBack));
        }
    }
    return needSendBack;
}

size_t* Buffer::getCapacityPtr()
{
    return &buf->capacity;
}

void Buffer::copy(char* start, char* end)
{
    memcpy(back(), start, end - start);
    buf->len += end - start;
}

int Buffer::ssEncryptAll(CipherEnv& cipherEnv)
{
    int err = ss_encrypt_all(&cipherEnv.cipher, buf.get(), buf->capacity);
    return err;
}

int Buffer::ssDecryptALl(CipherEnv& cipherEnv)
{
    int err = ss_decrypt_all(&cipherEnv.cipher, buf.get(), buf->capacity);
    return err;
}

void Buffer::protocolPluginUDPPreEncrypt(UDPRelay& connectionContext)
{
    if (connectionContext.protocol_plugin) {
        if (connectionContext.protocol_plugin->client_udp_pre_encrypt) {
            auto clientUdpPreEncrypt = connectionContext.protocol_plugin->client_udp_pre_encrypt;
            setLength(clientUdpPreEncrypt(connectionContext.protocolPtr.get(), getBufPtr(), buf->len, &buf->capacity));
        }
    }
}

void Buffer::protocolPluginUDPPostDecrypt(UDPRelay& connectionContext)
{
    if (connectionContext.protocol_plugin) {
        if (connectionContext.protocol_plugin->client_post_decrypt) {
            auto clientPostDecrypt = connectionContext.protocol_plugin->client_udp_post_decrypt;
            setLength(clientPostDecrypt(connectionContext.protocolPtr.get(), getBufPtr(), buf->len, &buf->capacity));
        }
    }
}
char* Buffer::end()
{
    if (buf)
        return buf->array + buf->capacity;
    return nullptr;
}
