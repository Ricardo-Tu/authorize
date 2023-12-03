#include "../../../headerfiles/crypto/rsa/scrsa.h"

BIGNUM *scrsa::generatePrime(int bits)
{
    BIGNUM *p = BN_new();
    BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL);
    return p;
}

// n = p * q
BIGNUM *scrsa::generateModulus(BIGNUM *q, BIGNUM *p)
{

    BIGNUM *n = BN_new();

    BN_mul(n, p, q, BN_CTX_new());

    BN_free(p);
    BN_free(q);

    return n;
}

BIGNUM *scrsa::euler(BIGNUM *p, BIGNUM *q)
{
    BIGNUM *one = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *tmp = BN_new();
    BN_one(one);

    // phi = (p - 1) * (q - 1)
    BN_sub(phi, p, one);
    BN_sub(tmp, q, one);
    BN_mul(phi, phi, tmp, BN_CTX_new());

    BN_free(one);
    BN_free(tmp);

    return phi;
}

BIGNUM *scrsa::choose_public_exponent(const BIGNUM *phi_n)
{
    BIGNUM *e = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *temp = BN_new();

    BN_one(one);
    BN_copy(e, one);

    BN_add(e, e, one);

    while (BN_cmp(e, phi_n) < 0)
    {
        BN_gcd(gcd, e, phi_n, BN_CTX_new());
        if (BN_cmp(gcd, one) == 0)
        {
            break;
        }

        BN_add(e, e, one);
    }

    BN_free(gcd);
    BN_free(one);
    BN_free(temp);

    return e;
}

// private key

BIGNUM *scrsa::generatePrivateKey(const BIGNUM *e, const BIGNUM *phi_n)
{
    BIGNUM *d = BN_new();
    BIGNUM *temp = BN_new();

    BN_mod_inverse(d, e, phi_n, BN_CTX_new());

    if (BN_is_negative(d))
    {
        BN_add(d, d, phi_n);
    }

    BN_free(temp);

    return d;
}

BIGNUM *scrsa::text_to_number(const std::string &text)
{
    BIGNUM *num = BN_new();

    for (char c : text)
    {
        BN_mul_word(num, 256);
        BN_add_word(num, static_cast<unsigned char>(c));
    }

    return num;
}

BIGNUM *scrsa::read_and_convert_file(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return nullptr;
    }

    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize > 50 * 1024 * 1024)
    {
        std::cerr << "File size exceeds the limit of 50 MB." << std::endl;
        return nullptr;
    }

    std::string buffer;
    buffer.resize(fileSize);

    file.read(&buffer[0], fileSize);

    file.close();

    BIGNUM *m = text_to_number(buffer);

    return m;
}

bool scrsa::number_to_text(const BIGNUM *num, const std::string &filename)
{
    int size = BN_num_bytes(num);

    std::vector<unsigned char> buffer(size);

    BN_bn2bin(num, buffer.data());

    std::string text;
    for (unsigned char byte : buffer)
    {
        text += static_cast<char>(byte);
    }

    std::ofstream file(filename);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }
    file << text;
    file.close();

    std::cout << "Decrypted text in string view: " << text << std::endl;

    return true;
}

bool scrsa::write_bignums_to_file(const BIGNUM *num1, const BIGNUM *num2, const std::string &filename)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    int size1 = BN_num_bytes(num1);
    int size2 = BN_num_bytes(num2);

    std::vector<unsigned char> buffer1(size1);
    std::vector<unsigned char> buffer2(size2);

    BN_bn2bin(num1, buffer1.data());
    BN_bn2bin(num2, buffer2.data());

    file.write(reinterpret_cast<char *>(buffer1.data()), size1);
    file.write(reinterpret_cast<char *>(buffer2.data()), size2);

    file.close();

    return true;
}

bool scrsa::write_bignum_to_file(const BIGNUM *num, const std::string &filename)
{
    std::fstream fs;
    fs.open(filename, std::ios::in);
    if (!fs)
    {
        std::ofstream fout(filename);
        if (fout)
        {
            fout.close();
            std::cerr << "Failed to open file,then craete new file." << filename << std::endl;
        }
    }
    else
        fs.close();
    std::ofstream file(filename, std::ios::binary);

    int size = BN_num_bytes(num);

    std::vector<unsigned char> buffer(size);

    BN_bn2bin(num, buffer.data());

    file.write(reinterpret_cast<char *>(buffer.data()), size);

    file.close();

    return true;
}

BIGNUM *scrsa::read_text_to_bignum(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return nullptr;
    }

    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize > 50 * 1024 * 1024)
    {
        std::cerr << "File size exceeds the limit of 50 MB." << std::endl;
        return nullptr;
    }

    std::string buffer;
    buffer.resize(fileSize);

    file.read(&buffer[0], fileSize);

    file.close();

    BIGNUM *num = text_to_number(buffer);

    return num;
}

// encrypt
BIGNUM *scrsa::encrypt_message(const BIGNUM *m, const BIGNUM *e, const BIGNUM *n)
{
    BIGNUM *C = BN_new();

    BN_mod_exp(C, m, e, n, BN_CTX_new());

    return C;
}

// decrypt
BIGNUM *scrsa::decrypt_message(BIGNUM *enc_text, BIGNUM *prv_key, BIGNUM *n)
{
    BIGNUM *dec_text = BN_new();

    BN_mod_exp(dec_text, enc_text, prv_key, n, BN_CTX_new());

    return dec_text;
}

std::string scrsa::number_to_string(const BIGNUM *num)
{
    int size = BN_num_bytes(num);

    std::vector<unsigned char> buffer(size);

    BN_bn2bin(num, buffer.data());

    std::string text;
    for (unsigned char byte : buffer)
    {
        text += static_cast<char>(byte);
    }
    return text;
}


bool scrsa::generate_keys(
    std::string &str_public_key,
    std::string &str_n,
    std::string &str_private_key,
    int bits)
{
    bool retflag = true;
    BIGNUM *p = this->generatePrime(bits);
    BIGNUM *q = this->generatePrime(bits);
    BIGNUM *fi = BN_new();
    fi = euler(p, q);
    char *p_1 = BN_bn2dec(p);
    char *q_1 = BN_bn2dec(q);
    BIGNUM *n = generateModulus(q, p);
    char *n_1 = BN_bn2dec(n);
    char *phiStr = BN_bn2dec(fi);
    BIGNUM *pub_key = choose_public_exponent(fi);
    BIGNUM *prv_key = generatePrivateKey(pub_key, fi);
    char *prvt = BN_bn2dec(prv_key);
    int size = BN_num_bytes(prv_key);
    std::vector<unsigned char> buffer(size);
    BN_bn2bin(prv_key, buffer.data());
    str_public_key = bignumToString(pub_key);
    str_n = bignumToString(n);
    str_private_key = bignumToString(prv_key);
    BN_free(p);
    BN_free(q);
    BN_free(fi);
    BN_free(n);
    BN_free(pub_key);
    BN_free(prv_key);
    OPENSSL_free(p_1);
    OPENSSL_free(q_1);
    OPENSSL_free(n_1);
    OPENSSL_free(phiStr);
    OPENSSL_free(prvt);
    return retflag;
}

std::string scrsa::encrypt_string(
    const std::string StrPublickey,
    const std::string Str_n,
    const std::string StrText)
{
    std::string str = number_to_string(text_to_number(StrText));
    BIGNUM *n = stringToBignum(Str_n);
    BIGNUM *public_key = stringToBignum(StrPublickey);
    BIGNUM *text = text_to_number(StrText);
    BIGNUM *encryptedText = encrypt_message(text, public_key, n);
    std::string StrEncryptedText = number_to_string(encryptedText);
    BN_free(n);
    BN_free(public_key);
    BN_free(text);
    BN_free(encryptedText);
    return StrEncryptedText;
}

std::string scrsa::decrypt_string(
    const std::string strPrivateKey,
    const std::string str_n,
    const std::string strEncryptedText)
{
    BIGNUM *n = stringToBignum(str_n);
    BIGNUM *privateKey = stringToBignum(strPrivateKey);
    BIGNUM *encryptedText = text_to_number(strEncryptedText);
    BIGNUM *decryptedText = decrypt_message(encryptedText, privateKey, n);
    std::string strDecryptedText = number_to_string(decryptedText);
    BN_free(n);
    BN_free(privateKey);
    BN_free(encryptedText);
    BN_free(decryptedText);
    return strDecryptedText;
}

std::string num_to_ascii(const BIGNUM* num) {
    std::string asciiStr;
    BIGNUM* temp = BN_dup(num);
    BIGNUM* rem = BN_new();

    while (BN_cmp(temp, BN_value_one()) > 0) {
        BN_div(temp, rem, temp, BN_value_one(), BN_CTX_new());
        char c = static_cast<char>(BN_get_word(rem));
        asciiStr += c;
    }

    BN_free(temp);
    BN_free(rem);

    return std::string(asciiStr.rbegin(), asciiStr.rend());
}

std::string scrsa::bignumToString(const BIGNUM *bignum)
{
    char *hexString = BN_bn2hex(bignum);
    std::string result(hexString);
    OPENSSL_free(hexString);
    return result;
}

BIGNUM *scrsa::stringToBignum(const std::string &str)
{
    BIGNUM *bignum = BN_new();
    if (BN_hex2bn(&bignum, str.c_str()) == 0)
    {
        BN_free(bignum);
        return nullptr;
    }
    return bignum;
}

std::string sha1_hash(const std::string& str) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    std::string result;

    SHA1(reinterpret_cast<const unsigned char*>(str.c_str()), str.length(), hash);

    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        result += hash[i];
    }

    return result;
}

std::string hexToString(const std::string& text) {
    std::stringstream hexStream;
    
    // 将每个字符转换为对应的十六进制值
    for (char c : text) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    
    // 返回十六进制表示形式的字符串
    return hexStream.str();
}

std::string hexCharStrToString(const char buffer[],long buffer_size)
{
    std::stringstream hexStream;

    for(long i = 0; i < buffer_size; i++)
    {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    return hexStream.str();
}