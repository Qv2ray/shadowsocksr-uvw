#ifndef CIPHERENV_HPP
#define CIPHERENV_HPP
#include <memory>
#include "encrypt.h"

class CipherEnv{
public:
    cipher_env_t  cipher{};
    CipherEnv(const char* passwd,const char* method);
    ~CipherEnv();
};

#endif // CIPHERENV_HPP
