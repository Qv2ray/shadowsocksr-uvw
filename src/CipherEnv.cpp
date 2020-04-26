#include "CipherEnv.hpp"

CipherEnv::CipherEnv(const char* passwd, const char* method)
{
    memset(&cipher, 0, sizeof(cipher_env_t));
    enc_init(&cipher, passwd, method);
}

CipherEnv::~CipherEnv()
{
    enc_release(&cipher);
}
