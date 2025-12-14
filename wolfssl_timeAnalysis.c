#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    byte key[16], iv[12], plaintext[1024], ciphertext[1024 + 16], tag[16];
    int ciphertext_len = 0;

    // Random values
    wc_RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, key, sizeof(key));
    wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    wc_RNG_GenerateBlock(&rng, plaintext, sizeof(plaintext));

    Aes aes;
    wc_AesGcmSetKey(&aes, key, sizeof(key));

    wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext),
                     iv, sizeof(iv), tag, sizeof(tag));

    printf("%d\n", sizeof(plaintext)); // trivial output
    wc_FreeRng(&rng);
    return 0;
}
