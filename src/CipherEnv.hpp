#ifndef CIPHERENV_HPP
#define CIPHERENV_HPP
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#include <memory>
extern "C"
{
#include "encrypt.h"
}

class CipherEnv{
public:
    cipher_env_t  cipher{};
    CipherEnv(const char* passwd,const char* method);
    ~CipherEnv();
};

#endif // CIPHERENV_HPP
