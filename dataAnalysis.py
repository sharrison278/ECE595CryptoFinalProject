import sys
import os
import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# 1. Read input directory
# -----------------------------
if len(sys.argv) < 2:
    print("Usage: python dataAnalysis.py <results_directory>")
    sys.exit(1)

input_dir = sys.argv[1]

if not os.path.isdir(input_dir):
    print(f"Error: {input_dir} is not a directory")
    sys.exit(1)

# -----------------------------
# 2. Read and parse all results files
# -----------------------------
data = []

for fname in os.listdir(input_dir):
    if not fname.endswith(".txt"):
        continue
    path = os.path.join(input_dir, fname)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith('-') or line.startswith('Cipher Suite'):
            continue  # skip headers and separators
        parts = line.split()
        
        # Cipher Suite names can have spaces, so detect first integer as size
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

if not data:
    print("No valid data found in directory.")
    sys.exit(1)

df = pd.DataFrame(data)

# -----------------------------
# 3. Plot Mean encryption time
# -----------------------------
plt.figure(figsize=(10,6))
for cipher in df['Cipher'].unique():
    subset = df[df['Cipher'] == cipher]
    # Optionally, show mean of multiple runs if duplicates exist
    subset_grouped = subset.groupby('Size')['Mean_us'].mean().reset_index()
    plt.plot(subset_grouped['Size'], subset_grouped['Mean_us'], marker='o', label=cipher)

plt.xscale('log')
plt.yscale('log')
plt.xlabel("Message Size (Bytes)")
plt.ylabel("Mean Encryption Time (µs)")
plt.title("Encryption Time vs Message Size")
plt.legend()
plt.grid(True, which="both", ls="--", lw=0.5)
plt.tight_layout()

mean_plot_file = os.path.join(input_dir, "mean_encryption_time.png")
plt.savefig(mean_plot_file)
print(f"Saved plot: {mean_plot_file}")
plt.show()
plt.close()

# -----------------------------
# 4. Plot MB/s throughput
# -----------------------------
plt.figure(figsize=(10,6))
for cipher in df['Cipher'].unique():
    subset = df[df['Cipher'] == cipher]
    subset_grouped = subset.groupby('Size')['MBps'].mean().reset_index()
    plt.plot(subset_grouped['Size'], subset_grouped['MBps'], marker='o', label=cipher)

plt.xscale('log')
plt.xlabel("Message Size (Bytes)")
plt.ylabel("Throughput (MB/s)")
plt.title("Encryption Throughput vs Message Size")
plt.legend()
plt.grid(True, which="both", ls="--", lw=0.5)
plt.tight_layout()

mbps_plot_file = os.path.join(input_dir, "throughput.png")
plt.savefig(mbps_plot_file)
print(f"Saved plot: {mbps_plot_file}")
plt.show()
plt.close()