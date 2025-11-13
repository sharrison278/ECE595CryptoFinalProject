import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# 1. Read and parse results.txt
# -----------------------------
data = []

with open("results.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

for line in lines:
    line = line.strip()
    if not line or line.startswith('-') or line.startswith('Cipher Suite'):
        continue  # skip headers and separators
    parts = line.split()
    
    # Cipher Suite names can have spaces, so we detect them
    size_index = next(i for i, p in enumerate(parts) if p.isdigit())
    cipher_name = " ".join(parts[:size_index])
    size = int(parts[size_index])
    mean_us = float(parts[size_index + 1])
    std_us = float(parts[size_index + 2])
    mbps = float(parts[size_index + 3])
    
    data.append({
        "Cipher": cipher_name,
        "Size": size,
        "Mean_us": mean_us,
        "Std_us": std_us,
        "MBps": mbps
    })

df = pd.DataFrame(data)

# -----------------------------
# 2. Plot Mean encryption time
# -----------------------------
plt.figure(figsize=(10,6))
for cipher in df['Cipher'].unique():
    subset = df[df['Cipher'] == cipher]
    plt.plot(subset['Size'], subset['Mean_us'], marker='o', label=cipher)

plt.xscale('log')
plt.yscale('log')
plt.xlabel("Message Size (Bytes)")
plt.ylabel("Mean Encryption Time (µs)")
plt.title("Encryption Time vs Message Size")
plt.legend()
plt.grid(True, which="both", ls="--", lw=0.5)
plt.tight_layout()
plt.show()

# -----------------------------
# 3. Plot MB/s throughput
# -----------------------------
plt.figure(figsize=(10,6))
for cipher in df['Cipher'].unique():
    subset = df[df['Cipher'] == cipher]
    plt.plot(subset['Size'], subset['MBps'], marker='o', label=cipher)

plt.xscale('log')
plt.xlabel("Message Size (Bytes)")
plt.ylabel("Throughput (MB/s)")
plt.title("Encryption Throughput vs Message Size")
plt.legend()
plt.grid(True, which="both", ls="--", lw=0.5)
plt.tight_layout()
plt.show()
