//#include "generateKey.h"
#include "scrsa.h"

bool generateRsaKey()
{
    bool retflag = true;
    //sql::Driver *driver;
    //sql::Connection *connect;
    //std::string hostname_port = "tcp://172.18.1.112:30003";
    //std::string username = "root";
    //std::string password = "123456";
    //std::string database = "keypair";
    //driver = get_driver_instance();
    //connect = driver->connect(hostname_port, username, password);
    //connect->setSchema(database);
    //sql::Statement *stmt;
    //stmt = connect->createStatement();
    scrsa rsa;

    BIGNUM *p = rsa.generatePrime(2048);
    BIGNUM *q = rsa.generatePrime(2048);
    BIGNUM *fi = BN_new();
    fi = rsa.euler(p, q);

    char *p_1 = BN_bn2dec(p);
    char *q_1 = BN_bn2dec(q);
    // std::cout << "Prime num p: " << p_1 << std::endl
    //           << std::endl;
    // std::cout << "Prime num q: " << q_1 << std::endl
    //           << std::endl;

    BIGNUM *n = rsa.generateModulus(q, p);
    char *n_1 = BN_bn2dec(n);
    // std::cout << "Module n (first key part): " << n_1 << std::endl
    //           << std::endl;

    char *phiStr = BN_bn2dec(fi);
    // std::cout << "Eiler (n): " << phiStr << std::endl
    //           << std::endl;

    BIGNUM *pub_key = rsa.choose_public_exponent(fi);

    // std::cout << "Public exponent e (second key part): " << BN_bn2dec(pub_key) << std::endl
    //           << std::endl;

    // std::cout << "Writing pub key to file..." << std::endl
    //           << std::endl;
    // std::string pubF = "./pub.txt";
    // write_bignums_to_file(n, pub_key, pubF);

    BIGNUM *prv_key = rsa.generatePrivateKey(pub_key, fi);
    char *prvt = BN_bn2dec(prv_key);
    // std::cout << "private key: " << prvt << std::endl
    //           << std::endl;

    // std::cout << "Writing private key to file..." << std::endl
    //           << std::endl;

    // std::string prvF = "./priv.txt";
    // write_bignum_to_file(prv_key, prvF);

    int size = BN_num_bytes(prv_key);
    std::vector<unsigned char> buffer(size);
    BN_bn2bin(prv_key, buffer.data());

    //try
    //{
    //    stmt->execute("INSERT INTO keylib (algorithem, length, n, publickey, privatekey, comment) VALUES ('rsa', '1024', '" + bignumToString(n) + "', '" + bignumToString(pub_key) + "', '" + bignumToString(prv_key) + "', 'first key pair')");
    //}
    //catch (sql::SQLException &e)
    //{
    //    std::cerr << "SQL error: " << e.what() << std::endl;
    //    retflag = false;
    //}

    std::ofstream nfile("./rsa-n.txt", std::ios::out | std::ios::binary);
    nfile << rsa.number_to_string(n);
    nfile.close();

    std::ofstream publicfile("./rsa-pub.txt", std::ios::out | std::ios::binary);
    publicfile << rsa.number_to_string(pub_key);
    publicfile.close();

    std::ofstream privatefile("./rsa-priv.txt", std::ios::out | std::ios::binary);
    privatefile << rsa.number_to_string(prv_key); 
    privatefile.close();

    //bignumToString(n) + "', '" + bignumToString(pub_key) + "', '" + bignumToString(prv_key)

    //delete stmt;
    //delete connect;

    return retflag;
}

int main(void)
{
    if (!generateRsaKey())
        std::cout << "Error" << std::endl;
    return 0;
}