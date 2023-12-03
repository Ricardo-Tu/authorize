#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <fstream>
#include <string>
#include <vector>


// Генерує велике просте число довжиною 1024 біти
BIGNUM* generatePrime(int bits) {
    BIGNUM* p = BN_new();
    BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL);
    return p;
}

//n = p * q
BIGNUM* generateModulus(BIGNUM* q,BIGNUM* p) {
  
    BIGNUM* n = BN_new();

    // Обчислюємо модуль n = p * q
    BN_mul(n, p, q, BN_CTX_new());

    BN_free(p);
    BN_free(q);

    return n;
}


BIGNUM* euler(BIGNUM* p, BIGNUM* q) {
    BIGNUM* one = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* tmp = BN_new();
    // Ініціалізуємо значення
    BN_one(one);

    // phi = (p - 1) * (q - 1)
    BN_sub(phi, p, one);
    BN_sub(tmp, q, one);
    BN_mul(phi, phi, tmp, BN_CTX_new());
    

    // Звільняємо пам'ять
    BN_free(one);
    BN_free(tmp);

    return phi;
}



BIGNUM* choose_public_exponent(const BIGNUM* phi_n) {
    BIGNUM* e = BN_new();
    BIGNUM* gcd = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* temp = BN_new();

    BN_one(one);
    BN_copy(e, one);

    // Починаємо перевірку з e = 2
    BN_add(e, e, one);

    while (BN_cmp(e, phi_n) < 0) {
        BN_gcd(gcd, e, phi_n, BN_CTX_new());
        if (BN_cmp(gcd, one) == 0) {
            // e і φ(n) є взаємно простими, тому закінчуємо цикл
            break;
        }

        BN_add(e, e, one);
    }

    // Звільняємо пам'ять
    BN_free(gcd);
    BN_free(one);
    BN_free(temp);

    return e;
}


//private key

BIGNUM* generatePrivateKey(const BIGNUM* e, const BIGNUM* phi_n) {
    BIGNUM* d = BN_new();
    BIGNUM* temp = BN_new();

    // Використовуємо розширений алгоритм Евкліда для обчислення експонента d
    BN_mod_inverse(d, e, phi_n, BN_CTX_new());

    // Переконуємося, що d є додатнім числом
    if (BN_is_negative(d)) {
        BN_add(d, d, phi_n);
    }

    // Звільняємо пам'ять
    BN_free(temp);

    return d;
}

