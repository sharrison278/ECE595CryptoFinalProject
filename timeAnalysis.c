#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main() {
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char plaintext[1024];  // Adjust size as needed
    unsigned char ciphertext[1024 + 16]; // + tag space
    unsigned char tag[16];

    int len, ciphertext_len;

    // Random key, IV, and plaintext
    if (!RAND_bytes(key, sizeof(key)) ||
        !RAND_bytes(iv, sizeof(iv)) ||
        !RAND_bytes(plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Random generation failed\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        return 1;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return 1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
        return 1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return 1;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return 1;

    EVP_CIPHER_CTX_free(ctx);

    // Optional: write ciphertext somewhere if you want
    printf("%d\n", ciphertext_len);  // output size as a trivial check
    return 0;
}
