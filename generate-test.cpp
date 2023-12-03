#include "./headerfiles/crypto/rsa/scrsa.h"

int main(void)
{
    std::string str_public_key;
    std::string str_n;
    std::string str_private_key;
    int bits = 4096;
    scrsa rsa;
    if(!rsa.generate_keys(str_public_key, str_n, str_private_key, bits))
    {
        std::cout << "Error generating keys" << std::endl;
        return 1;
    }
    return 0;
}