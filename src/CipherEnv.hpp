#ifndef CIPHERENV_HPP
#define CIPHERENV_HPP
#include "encrypt.h"

#include <memory>

class CipherEnv
{
public:
    cipher_env_t cipher {};
    CipherEnv(const char* passwd, const char* method);
    ~CipherEnv();
};

#endif // CIPHERENV_HPP
