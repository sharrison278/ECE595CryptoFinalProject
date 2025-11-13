import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from typing import List

# --- Configuration ---
# Number of times to run the encryption loop to gather statistics
NUM_ITERATIONS = 50000
# Size of the data to encrypt (in bytes). A larger payload helps reveal timing variance.
DATA_SIZE = 1024 * 64 # 64 KB payload

def setup_primitives():
    """Generates the keys and data needed for the experiment."""
    print(f"Setting up experiment with {DATA_SIZE // 1024} KB payload and {NUM_ITERATIONS} iterations...")

    # Keys must be 16 bytes (AES-128) or 32 bytes (ChaCha20-256)
    key_aes = os.urandom(16)
    key_chacha = os.urandom(32)

    # The data (plaintext) to be encrypted
    plaintext = os.urandom(DATA_SIZE)
    
    return key_aes, key_chacha, plaintext

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> float:
    """Performs AES-128-GCM encryption and returns the time taken in nanoseconds."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # Nonce must be unique for every encryption
    
    start = time.perf_counter_ns()
    aesgcm.encrypt(nonce, plaintext, None)
    end = time.perf_counter_ns()
    
    return end - start

def encrypt_chacha20_poly1305(key: bytes, plaintext: bytes) -> float:
    """Performs ChaCha20-Poly1305 encryption and returns the time taken in nanoseconds."""
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12) # Nonce must be unique for every encryption
    
    start = time.perf_counter_ns()
    chacha.encrypt(nonce, plaintext, None)
    end = time.perf_counter_ns()
    
    return end - start

def run_timing_experiment(key: bytes, plaintext: bytes, cipher_name: str, encrypt_func) -> List[float]:
    """Runs the timing loop for a given cipher function."""
    times = []
    print(f"\n--- Running experiment for {cipher_name} ({NUM_ITERATIONS} times) ---")
    
    for i in range(NUM_ITERATIONS):
        # We only time the encryption, not key/primitive setup (which is done once)
        # and we use fresh, random nonces for security, but this is timed inside the function.
        try:
            time_taken = encrypt_func(key, plaintext)
            times.append(time_taken)
        except Exception as e:
            # Catch errors but continue to ensure full data collection
            print(f"Error at iteration {i}: {e}")
            
    return times

def calculate_stats(times: List[float], cipher_name: str):
    """Calculates and prints the mean, standard deviation, and variance of the timing data."""
    if not times:
        print(f"No timing data collected for {cipher_name}.")
        return

    # Convert times from nanoseconds to microseconds (1,000 ns = 1 µs) for easier reading
    times_us = [t / 1000 for t in times]
    
    mean = sum(times_us) / len(times_us)
    variance = sum((t - mean) ** 2 for t in times_us) / len(times_us)
    std_dev = variance ** 0.5
    
    print("\n" + "="*50)
    print(f"Results for: {cipher_name}")
    print(f"Total Samples: {len(times)}")
    print(f"Mean Encryption Time: {mean:,.3f} µs (microseconds)")
    print(f"Standard Deviation (σ): {std_dev:,.3f} µs")
    # The Coefficient of Variation (CV = σ / mean) is a good measure of relative variance
    print(f"Coefficient of Variation (CV): {std_dev / mean * 100:.3f}%")
    print("="*50)
    
    # Differential Timing Analysis Insight:
    # A higher Standard Deviation (σ) and Coefficient of Variation (CV) suggest
    # that the operation time is highly sensitive to external factors (e.g., CPU cache state, 
    # S-box lookups). This variance is what is exploited in timing attacks.
    if std_dev / mean * 100 > 1.0:
        print(f"Observation: The {cipher_name} implementation shows significant timing variance relative to its mean.")

def main():
    """Main function to run the experiment."""
    try:
        key_aes, key_chacha, plaintext = setup_primitives()
    except Exception as e:
        print(f"Setup Error: {e}")
        return

    # 1. Run AES-GCM experiment
    aes_times = run_timing_experiment(
        key_aes, 
        plaintext, 
        "AES-128-GCM (Block Cipher)", 
        encrypt_aes_gcm
    )

    # 2. Run ChaCha20-Poly1305 experiment
    chacha_times = run_timing_experiment(
        key_chacha, 
        plaintext, 
        "ChaCha20-Poly1305 (Stream Cipher)", 
        encrypt_chacha20_poly1305
    )

    # 3. Calculate and display statistics
    calculate_stats(aes_times, "AES-128-GCM")
    calculate_stats(chacha_times, "ChaCha20-Poly1305")

if __name__ == "__main__":
    try:
        # Check for the required dependency
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        main()
    except ImportError:
        print("-" * 70)
        print("ERROR: The 'cryptography' library is required for this script.")
        print("Please install it using: pip install cryptography")
        print("-" * 70)
        
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
