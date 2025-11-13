
import os
import time
import statistics
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
from cryptography.hazmat.primitives import hashes, hmac

# -------------------------------------------------------------
# Cipher suite mapping (encryption primitives)
# -------------------------------------------------------------

CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256": "aes-128-gcm",
    "TLS_AES_256_GCM_SHA384": "aes-256-gcm",
    "TLS_CHACHA20_POLY1305_SHA256": "chacha20-poly1305",
    "TLS_AES_128_CCM_SHA256": "aes-128-ccm",
    "TLS_AES_128_CBC_SHA256": "aes-128-cbc",       # MAC-then-encrypt (HMAC-SHA256)
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": "3des-cbc",  # Legacy triple DES CBC
}

# -------------------------------------------------------------
# Configuration
# -------------------------------------------------------------
MESSAGE_SIZES = [16, 512, 1024, 16384, 65536]  # bytes
SAMPLES_PER_SIZE = 200
backend = default_backend()

# -------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------

def time_encrypt(func, iterations=SAMPLES_PER_SIZE):
    """Measure average encryption time for callable `func`."""
    timings = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        timings.append(end - start)
    return statistics.mean(timings), statistics.stdev(timings)


def run_aes_gcm(key_len, msg):
    key = os.urandom(key_len // 8)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    return lambda: aesgcm.encrypt(nonce, msg, None)


def run_chacha20_poly1305(msg):
    key = os.urandom(32)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    return lambda: chacha.encrypt(nonce, msg, None)


def run_aes_ccm(msg):
    key = os.urandom(16)
    nonce = os.urandom(11)
    aesccm = AESCCM(key)
    return lambda: aesccm.encrypt(nonce, msg, None)


def run_aes_cbc_hmac_sha256(msg):
    key = os.urandom(16)
    pad_len = 16 - (len(msg) % 16)
    padded = msg + bytes([pad_len]) * pad_len
    
    # Compute HMAC-SHA256 then encrypt (MAC-then-encrypt)
    def do_encrypt():
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()

            h = hmac.HMAC(key, hashes.SHA256())
            h.update(padded)
            tag = h.finalize()

            # update and finalize
            encryptor.update(padded + tag)
            encryptor.finalize()
        except:
            # Ignore if cryptography reuses internal context on last run
            pass

    return do_encrypt


def run_3des_cbc(msg):
    key = os.urandom(24)
    pad_len = 8 - (len(msg) % 8)
    padded = msg + bytes([pad_len]) * pad_len

    def do_encrpyt():
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        encryptor.update(padded)
        encryptor.finalize()

    return do_encrpyt

# -------------------------------------------------------------
# Benchmark all cipher suites
# -------------------------------------------------------------

def main():
    output_file = "results.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        # Write header
        f.write(f"{'Cipher Suite':45s} {'Size (B)':>10s} {'Mean (µs)':>12s} {'Std (µs)':>10s} {'MB/s':>10s}\n")
        f.write("-" * 90 + "\n")

        # print(f"{'Cipher Suite':45s} {'Size (B)':>10s} {'Mean (µs)':>12s} {'Std (µs)':>10s} {'MB/s':>10s}")
        # print("-" * 90)

        for suite, impl in CIPHER_SUITES.items():
            for size in MESSAGE_SIZES:
                msg = os.urandom(size)

                # Select encryptor function
                if impl == "aes-128-gcm":
                    encrypt_fn = run_aes_gcm(128, msg)
                elif impl == "aes-256-gcm":
                    encrypt_fn = run_aes_gcm(256, msg)
                elif impl == "chacha20-poly1305":
                    encrypt_fn = run_chacha20_poly1305(msg)
                elif impl == "aes-128-ccm":
                    encrypt_fn = run_aes_ccm(msg)
                elif impl == "aes-128-cbc":
                    encrypt_fn = run_aes_cbc_hmac_sha256(msg)
                elif impl == "3des-cbc":
                    encrypt_fn = run_3des_cbc(msg)
                else:
                    continue

                mean_ns, std_ns = time_encrypt(encrypt_fn)
                mean_us = mean_ns / 1000
                std_us = std_ns / 1000
                mbps = (size / (mean_ns / 1e9)) / (1024 * 1024)

                # print(f"{suite:45s} {size:10d} {mean_us:12.2f} {std_us:10.2f} {mbps:10.1f}")
                # Write results to file
                f.write(f"{suite:45s} {size:10d} {mean_us:12.2f} {std_us:10.2f} {mbps:10.1f}\n")
            f.write("-" * 90 + "\n")
        
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
