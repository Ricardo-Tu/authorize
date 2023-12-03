#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <fstream>
#include <string>
#include <vector>
#include <cppconn/driver.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include "files.h"

bool rsaDecryptoFile(const std::string &filename, BIGNUM *prv_key, BIGNUM *n)
{
    BIGNUM *enc_text = read_text_to_bignum(filename);
    BIGNUM *dec_text = decrypt_message(enc_text, prv_key, n);
    if (number_to_text(dec_text, "decrypted.txt"))
        return true;
    else
        return false;
}

int main(void)
{
    sql::Driver *driver;
    sql::Connection *connect;
    std::string hostname_port = "tcp://172.18.1.112:30003";
    std::string username = "root";
    std::string password = "123456";
    std::string database = "keypair";
    sql::ResultSet *res;
    driver = get_driver_instance();
    connect = driver->connect(hostname_port, username, password);
    connect->setSchema(database);
    sql::Statement *stmt;
    stmt = connect->createStatement();
    res = stmt->executeQuery("SELECT * FROM  keylib WHERE id = 2");

    int id;
    std::string algorithm;
    std::string length;
    std::string n;
    std::string publickey;
    std::string privatekey;
    std::string comment;
    // Process the result
    if (res->next())
    {
        id = res->getInt("id");
        algorithm = res->getString("algorithem");
        length = res->getInt("length");
        n = res->getString("n");
        publickey = res->getString("publickey");
        privatekey = res->getString("privatekey");
        comment = res->getString("comment");
        std::cout << "id: " << id << std::endl;
    }

    BIGNUM *n_mysql = stringToBignum(n);
    BIGNUM *private_mysql = stringToBignum(privatekey);

    // decrypt text
    BIGNUM *dec_text = decrypt_message(read_text_to_bignum("./encrypto_msg.txt"), private_mysql, n_mysql);

    std::cout << "Decrypted text : " << BN_bn2dec(dec_text) << std::endl;

    std::cout << "Writing decrypted text to file" << std::endl
              << std::endl;
    number_to_text(dec_text, "./dec.txt");

    return 0;
}