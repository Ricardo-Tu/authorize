#pragma once
#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <fstream>
#include <string>
#include <vector>

BIGNUM* generatePrime(int bits);
BIGNUM* generateModulus(BIGNUM* q, BIGNUM* p);
BIGNUM* euler(BIGNUM* p, BIGNUM* q);
BIGNUM* choose_public_exponent(const BIGNUM* phi_n);
BIGNUM* generatePrivateKey(const BIGNUM* e, const BIGNUM* phi_n);
BIGNUM* read_and_convert_file(const std::string& filename);
BIGNUM* encrypt_message(const BIGNUM* m, const BIGNUM* e, const BIGNUM* n);
BIGNUM* decrypt_message(BIGNUM* enc_text, BIGNUM* prv_key, BIGNUM* n);
bool number_to_text(const BIGNUM* num, const std::string& filename);
bool write_bignums_to_file(const BIGNUM* num1, const BIGNUM* num2, const std::string& filename);
bool write_bignum_to_file(const BIGNUM* num, const std::string& filename);
BIGNUM* read_text_to_bignum(const std::string& filename);
std::string bignumToString(const BIGNUM *bignum);
BIGNUM *stringToBignum(const std::string &str);