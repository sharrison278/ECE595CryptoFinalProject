#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <time.h>

int main() {
    byte key[16];
    byte iv[12];
    byte plaintext[1024];      // Adjust size as needed
    byte ciphertext[1024];     // ciphertext same size as plaintext
    byte tag[16];

    // Random key, IV, and plaintext
    srand((unsigned int)time(NULL));
    for (int i = 0; i < sizeof(key); i++) key[i] = rand() % 256;
    for (int i = 0; i < sizeof(iv); i++) iv[i] = rand() % 256;
    for (int i = 0; i < sizeof(plaintext); i++) plaintext[i] = rand() % 256;

    Aes aes;
    int ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
    if (ret != 0) {
        fprintf(stderr, "Failed to set AES key: %d\n", ret);
        return 1;
    }

    // No additional authenticated data (AAD), length 0
    const byte* aad = NULL;
    word32 aadLen = 0;

    ret = wc_AesGcmEncrypt(&aes,
                           plaintext, sizeof(plaintext),  // input
                           ciphertext,                   // output
                           iv, sizeof(iv),               // IV
                           aad, aadLen,                  // AAD (optional)
                           tag, sizeof(tag));            // authentication tag

    if (ret != 0) {
        fprintf(stderr, "Encryption failed: %d\n", ret);
        return 1;
    }

    // Output length for consistency with other benchmarks
    printf("%lu\n", sizeof(plaintext));

    return 0;
}
