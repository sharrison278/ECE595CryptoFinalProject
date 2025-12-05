
import os
import time
import warnings
import argparse
import statistics
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from Crypto.Cipher import DES, Blowfish, AES, Salsa20
# IDEA and Camellia ?
from Crypto.Random import get_random_bytes

# -------------------------------------------------------------
# Configuration
# -------------------------------------------------------------
MESSAGE_SIZES = [16, 512, 1024, 16384, 65536]  # in bytes
SAMPLES_PER_SIZE = 200
backend = default_backend()

# -------------------------------------------------------------
# Library Definitions 
# -------------------------------------------------------------

LIBRARIES = {
    "AES-128-GCM": {
        "encrypt": lambda msg: run_aes_gcm(128, msg)
    },
    "AES-256-GCM": {
        "encrypt": lambda msg: run_aes_gcm(256, msg)
    },
    "ChaCha20-Poly1305": {
        "encrypt": lambda msg: run_chacha20_poly1305(msg)
    },
    "AES-128-CCM": {
        "encrypt": lambda msg: run_aes_ccm(msg)
    },
    "3DES-CBC": {
        "encrypt": lambda msg: run_3des_cbc(msg)
    },
    "DES-ECB": {
        "encrypt": lambda msg: run_des(msg)
    },
    "Blowfish-ECB": {
        "encrypt": lambda msg: run_blowfish(msg)
    },
    # "Camellia-ECB": {
    #     "encrypt": lambda msg: run_camellia(msg)
    # },
    # "IDEA-ECB": {
    #     "encrypt": lambda msg: run_idea(msg)
    # },
    "Serpent-ECB": {
        "encrypt": lambda msg: run_serpent(msg)
    },
    "AES-GCM-SIV": {
        "encrypt": lambda msg: run_aes_gcm_siv(msg)
    },
    "Salsa20": {
        "encrypt": lambda msg: run_salsa20(msg)
    }
}


# -------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------

def time_operation(func, iterations=SAMPLES_PER_SIZE, record_avg=False):
    timings = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        timings.append(end - start)

    if not record_avg:
        return timings
    else:
        mean = statistics.mean(timings)
        std  = statistics.stdev(timings)
        return mean, std
    
# ------------------------
# Decryption 
# ------------------------

def run_aes_gcm_dec(key_len, msg):
    key = os.urandom(key_len // 8)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, msg, None)

    return lambda: aesgcm.decrypt(nonce, ciphertext, None)

def run_chacha20_poly1305_dec(msg):
    key = os.urandom(32)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ct = chacha.encrypt(nonce, msg, None)

    return lambda: chacha.decrypt(nonce, ct, None)

def run_aes_ccm_dec(msg):
    key = os.urandom(16)
    nonce = os.urandom(11)
    aesccm = AESCCM(key)
    ct = aesccm.encrypt(nonce, msg, None)

    return lambda: aesccm.decrypt(nonce, ct, None)

def run_aes_cbc_hmac_sha256_dec(msg):
    key = os.urandom(16)
    pad_len = 16 - (len(msg) % 16)
    padded = msg + bytes([pad_len]) * pad_len

    # Encrypt once to have ciphertext
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(padded)
    tag = h.finalize()

    ciphertext = encryptor.update(padded + tag) + encryptor.finalize()

    def decrypt_fn():
        cipher_d = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher_d.decryptor()
        pt_with_tag = decryptor.update(ciphertext) + decryptor.finalize()

        # split padded data + HMAC
        pt = pt_with_tag[:-32]
        recv_tag = pt_with_tag[-32:]

        # verify MAC
        h2 = hmac.HMAC(key, hashes.SHA256())
        h2.update(pt)
        try:
            h2.verify(recv_tag)
        except Exception:
            pass  # ignore failures

    return decrypt_fn

def run_3des_cbc_dec(msg):
    key = os.urandom(24)
    pad_len = 8 - (len(msg) % 8)
    padded = msg + bytes([pad_len]) * pad_len

    iv = os.urandom(8)
    warnings.filterwarnings("ignore")
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    def dec_fn():
        warnings.filterwarnings("ignore")
        cipher_d = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher_d.decryptor()
        decryptor.update(ciphertext)
        decryptor.finalize()

    return dec_fn

# ------------------------
# Diffe-Hellman KE & HMAC 
# ------------------------

def run_ecdh():
    # Generate ephemeral key pairs once
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())

    public_key_b = private_key_b.public_key()

    # Benchmark: compute shared secret
    return lambda: private_key_a.exchange(ec.ECDH(), public_key_b)

def run_hmac_sha256(msg):
    key = os.urandom(32)

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    tag = h.finalize()

    def mac_fn():
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(msg)
        h.verify(tag)

    return mac_fn

# ------------------------
# encryption 
# ------------------------

# def run_rsa(msg):
#     # Generate RSA key pair
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#     )
#     public_key = private_key.public_key()
#     # Function to encrypt the message
#     def encrypt():
#         return public_key.encrypt(
#             msg,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None)
#         )

#     return encrypt

def run_des(msg):
    key = get_random_bytes(8)  # DES key is 8 bytes
    cipher = DES.new(key, DES.MODE_ECB)
    padded_msg = msg + b' ' * (8 - len(msg) % 8)  # Simple padding
    return lambda: cipher.encrypt(padded_msg)

def run_blowfish(msg):
    key = get_random_bytes(16)  # Blowfish supports 4-56 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_msg = msg + b' ' * (8 - len(msg) % 8)
    return lambda: cipher.encrypt(padded_msg)

def run_camellia(msg):
    key = get_random_bytes(16)  # Camellia: 16, 24, 32 bytes
    cipher = Camellia.new(key, Camellia.MODE_ECB)
    padded_msg = msg + b' ' * (16 - len(msg) % 16)
    return lambda: cipher.encrypt(padded_msg)

def run_idea(msg):
    key = get_random_bytes(16)  # IDEA key is 16 bytes
    cipher = IDEA.new(key, IDEA.MODE_ECB)
    padded_msg = msg + b' ' * (8 - len(msg) % 8)
    return lambda: cipher.encrypt(padded_msg)

def run_serpent(msg):
    key = get_random_bytes(16)  # Serpent supports 16, 24, 32 bytes
    cipher = AES.new(key, AES.MODE_ECB)  # PyCryptodome doesn’t have Serpent natively
    # Placeholder: you need a Serpent implementation or library
    padded_msg = msg + b' ' * (16 - len(msg) % 16)
    return lambda: cipher.encrypt(padded_msg)

def run_aes_gcm_siv(msg):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM-SIV requires specialized lib
    key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)  # For actual GCM-SIV, consider pyca/cryptography >= 40
    return lambda: aesgcm.encrypt(nonce, msg, None)

def run_salsa20(msg):
    key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    cipher = Salsa20.new(key=key, nonce=nonce)
    return lambda: cipher.encrypt(msg)

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
        warnings.filterwarnings("ignore") # we already know 3DES is depricated
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        encryptor.update(padded)
        encryptor.finalize()

    return do_encrpyt

# -------------------------------------------------------------
# Benchmark all cipher suites
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Unified Crypto Timing Benchmark")
    parser.add_argument(
        "-o", "--output",
        default="results.txt",
        help="Output filename for benchmark results (default: results.txt)"
    )
    args = parser.parse_args()
    output_file = args.output

    with open(output_file, "w", encoding="utf-8") as f:

        # HEADER
        f.write(f"{'Library':35s} {'Size (B)':>10s} {'Time_ns':>12s}\n")
        f.write("-" * 60 + "\n")

        # PER-LIBRARY BENCHMARKS
        for lib_name, ops in LIBRARIES.items():

            for size in MESSAGE_SIZES: # [16, 512, 1024, 16384, 65536]  # in bytes
                msg = os.urandom(size)

                encrypt_fn = ops["encrypt"](msg)
                for t in time_operation(encrypt_fn, record_avg=False):
                    f.write(f"{lib_name:35s} {size:10d} {t:12d}\n")

            f.write("-" * 60 + "\n")


    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
