#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <time.h>

int main() {
    byte key[16];
    byte iv[12];
    byte plaintext[1024];        // Adjust size as needed
    byte ciphertext[1024];       // ciphertext same size as plaintext
    byte tag[16];

    // Random key, IV, and plaintext (simple RNG for example)
    srand((unsigned int)time(NULL));
    for (int i = 0; i < sizeof(key); i++) key[i] = rand() % 256;
    for (int i = 0; i < sizeof(iv); i++) iv[i] = rand() % 256;
    for (int i = 0; i < sizeof(plaintext); i++) plaintext[i] = rand() % 256;

    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);

    int ret = wc_AesGcmEncrypt(&aes,
                               plaintext, sizeof(plaintext),  // input
                               ciphertext,                   // output
                               iv, sizeof(iv),               // IV
                               tag, sizeof(tag));            // tag

    if (ret != 0) {
        fprintf(stderr, "Encryption failed: %d\n", ret);
        wc_AesFree(&aes);
        return 1;
    }

    wc_AesFree(&aes);

    // Output length for consistency with other benchmarks
    printf("%lu\n", sizeof(plaintext));
    return 0;
}
