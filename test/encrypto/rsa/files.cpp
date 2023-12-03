#include "files.h"

BIGNUM *text_to_number(const std::string &text)
{
    BIGNUM *num = BN_new();

    for (char c : text)
    {
        BN_mul_word(num, 256);
        BN_add_word(num, static_cast<unsigned char>(c));
    }

    return num;
}

BIGNUM *read_and_convert_file(const std::string &filename)
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

bool number_to_text(const BIGNUM *num, const std::string &filename)
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

bool write_bignums_to_file(const BIGNUM *num1, const BIGNUM *num2, const std::string &filename)
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

bool write_bignum_to_file(const BIGNUM *num, const std::string &filename)
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

BIGNUM *read_text_to_bignum(const std::string &filename)
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
BIGNUM *encrypt_message(const BIGNUM *m, const BIGNUM *e, const BIGNUM *n)
{
    BIGNUM *C = BN_new();

    BN_mod_exp(C, m, e, n, BN_CTX_new());

    return C;
}

// decrypt
BIGNUM *decrypt_message(BIGNUM *enc_text, BIGNUM *prv_key, BIGNUM *n)
{
    BIGNUM *dec_text = BN_new();

    BN_mod_exp(dec_text, enc_text, prv_key, n, BN_CTX_new());

    return dec_text;
}

std::string bignumToString(const BIGNUM *bignum)
{
    char *hexString = BN_bn2hex(bignum);
    std::string result(hexString);
    OPENSSL_free(hexString);
    return result;
}

BIGNUM *stringToBignum(const std::string &str)
{
    BIGNUM *bignum = BN_new();
    if (BN_hex2bn(&bignum, str.c_str()) == 0)
    {
        BN_free(bignum);
        return nullptr;
    }
    return bignum;
}

