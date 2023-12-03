#pragma once
#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <fstream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <iomanip>

class scrsa
{
private:
    /* data */
public:
    BIGNUM *read_and_convert_file(const std::string &filename);
    bool number_to_text(const BIGNUM *num, const std::string &filename);
    BIGNUM *text_to_number(const std::string &text);
    std::string number_to_string(const BIGNUM *num);
    bool write_bignums_to_file(const BIGNUM *num1, const BIGNUM *num2, const std::string &filename);
    bool write_bignum_to_file(const BIGNUM *num, const std::string &filename);
    BIGNUM *read_text_to_bignum(const std::string &filename);
    std::string bignumToString(const BIGNUM *bignum);
    BIGNUM *stringToBignum(const std::string &str);
    BIGNUM *encrypt_message(const BIGNUM *m, const BIGNUM *e, const BIGNUM *n);
    BIGNUM *decrypt_message(BIGNUM *enc_text, BIGNUM *prv_key, BIGNUM *n);
    BIGNUM *generatePrime(int bits);
    BIGNUM *generateModulus(BIGNUM *q, BIGNUM *p);
    BIGNUM *euler(BIGNUM *p, BIGNUM *q);
    BIGNUM *choose_public_exponent(const BIGNUM *phi_n);
    BIGNUM *generatePrivateKey(const BIGNUM *e, const BIGNUM *phi_n);
    bool generate_keys(
        std::string &str_public_key,
        std::string &str_n,
        std::string &str_private_key,
        int bits);
    std::string encrypt_string(
        const std::string strPublickey,
        const std::string str_n,
        const std::string strText);
    std::string decrypt_string(
        const std::string strPrivateKey,
        const std::string str_n,
        const std::string strEncryptedText);
};

std::string sha1_hash(const std::string& str);