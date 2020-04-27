#ifndef SSRUVBUFFER_H
#define SSRUVBUFFER_H
#include <memory>
extern "C"
{
#include "encrypt.h"
}
class CipherEnv;
class ObfsClass;
class ConnectionContext;
class UDPRelay;
namespace uvw
{
struct DataEvent;
struct UDPDataEvent;
}
class Buffer
{
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
public:
    Buffer();
    size_t* getLengthPtr();
    static buffer_t* newBuf();
    char operator[](int idx);
    char** getBufPtr(); // for compatiable c code.
    char* back();
    char* begin();
    char* end();
    void clear();
    void drop(size_t size);
    void bufRealloc(size_t size);
    std::unique_ptr<char[]> duplicateDataToArray();
    void copy(const uvw::DataEvent& event);
    void copy(const uvw::UDPDataEvent& event);
    void copyFromBegin(const uvw::DataEvent& event, int length = -1);
    void copyFromBegin(char* start, size_t size);
    void copy(const Buffer& that);
    void setLength(int l);
    size_t length();
    void protocolPluginUDPPreEncrypt(UDPRelay& connectionContext);
    void protocolPluginUDPPostDecrypt(UDPRelay& connectionContext);
    void protocolPluginPreEncrypt(ObfsClass& obfsClass, ConnectionContext& connectionContext);
    void protocolPluginPostDecrypt(ObfsClass& obfsClass, ConnectionContext& connectionContext);
    int ssEncrypt(CipherEnv& cipherEnv, ConnectionContext& connectionContext);
    int ssDecrypt(CipherEnv& cipherEnv, ConnectionContext& connectionContext);
    int ssEncryptAll(CipherEnv& cipherEnv);
    int ssDecryptALl(CipherEnv& cipherEnv);
    void clientEncode(ObfsClass& obfsClass, ConnectionContext& connectionContext, int encodeLen = -1);
    int clientDecode(ObfsClass& obfsClass, ConnectionContext& connectionContext);
    size_t* getCapacityPtr();

public:
    static constexpr size_t BUF_DEFAULT_CAPACITY = 2048;

private:
    std::unique_ptr<buffer_t, void (*)(buffer_t*)> buf;
    void copy(char* start, char* end);
};
#endif // SSRUVBUFFER_H
