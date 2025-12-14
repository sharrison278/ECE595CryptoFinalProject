#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <time.h>

#define PLAINTEXT_SIZE 65536  // adjust as needed
#define AES_KEY_SIZE   16     // AES-128
#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16

int main() {
    byte key[AES_KEY_SIZE];
    byte iv[GCM_IV_SIZE];
    byte plaintext[PLAINTEXT_SIZE];
    byte ciphertext[PLAINTEXT_SIZE];
    byte tag[GCM_TAG_SIZE];
    Aes aes;

    // Seed RNG
    srand((unsigned int)time(NULL));

    // Random key, IV, and plaintext
    for (int i = 0; i < AES_KEY_SIZE; i++) key[i] = rand() % 256;
    for (int i = 0; i < GCM_IV_SIZE; i++) iv[i] = rand() % 256;
    for (int i = 0; i < PLAINTEXT_SIZE; i++) plaintext[i] = rand() % 256;

    // Initialize AES structure
    wc_AesInit(&aes, NULL, INVALID_DEVID);

    // Encrypt using AES-GCM
    int ret = wc_AesGcmEncrypt(&aes,
                               plaintext, sizeof(plaintext),  // input
                               ciphertext,                  // output
                               iv, sizeof(iv),              // IV
                               tag, sizeof(tag));           // tag
    if (ret != 0) {
        fprintf(stderr, "Encryption failed: %d\n", ret);
        wc_AesFree(&aes);
        return 1;
    }

    // Clean up
    wc_AesFree(&aes);

    // Print ciphertext size as trivial check
    printf("%lu\n", sizeof(plaintext));
    return 0;
}
