#
# dataAnalysis.py
# Runs analysis on collected timing data and compares crypto libraries.
#

import sys
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import mannwhitneyu
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from statsmodels.distributions.empirical_distribution import ECDF


# -----------------------------
# Input / Output directories
# -----------------------------
if len(sys.argv) < 3:
    print("Usage: python dataAnalysis.py <results_directory> <plots_directory>")
    sys.exit(1)

input_dir = sys.argv[1]
figure_dir = sys.argv[2]

if not os.path.isdir(input_dir):
    print(f"Error: {input_dir} is not a directory")
    sys.exit(1)
os.makedirs(figure_dir, exist_ok=True)

# -----------------------------
# Read and parse results files
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
        if not line or line.startswith('-') or line.startswith('Library'):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        # Everything except last 2 parts is library name
        library = " ".join(parts[:-2])
        time_ns = float(parts[-1]) if parts[-1] != '-' else None
        if time_ns is None:
            continue

        time_us = time_ns / 1000.0
        data.append({"Library": library, "Time_us": time_us})

df = pd.DataFrame(data)
if df.empty:
    print("No valid data found.")
    sys.exit(1)

# -----------------------------
# Detect OpenSSL version from library name
# -----------------------------
def extract_openssl_version(lib_name):
    lib_lower = lib_name.lower()
    if 'openssl_1_1_1' in lib_lower:
        return 'OpenSSL 1.1.1'
    elif 'openssl_3_0' in lib_lower:
        return 'OpenSSL 3.0'
    elif 'boringssl_aes128gcm' in lib_lower:
        return 'BoringSSL'
    elif 'libressl_aes128gcm' in lib_lower:
        return 'LibreSSL'
    else:
        return 'Other'

df['Version'] = df['Library'].apply(extract_openssl_version)

# -----------------------------
# Compute enhanced statistics per library and version
# -----------------------------
stat_file = os.path.join(figure_dir, "stats.txt")
with open(stat_file, "w") as f:
    f.write("=== Library Statistics ===\n\n")
    header = "{:<25s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s}".format(
        "Library", "Mean(us)", "Median(us)", "Std(us)", "Min(us)", "Max(us)"
    )
    print(header)
    f.write(header + "\n")

    for lib in df['Library'].unique():
        subset = df[df['Library']==lib]
        times = subset['Time_us'].values
        line = "{:<25s} {:>10.2f} {:>10.2f} {:>10.2f} {:>10.2f} {:>10.2f}".format(
            lib, times.mean(), np.median(times), times.std(), times.min(), times.max()
        )
        print(line)
        f.write(line + "\n")

    f.write("\n=== OpenSSL Version Statistics ===\n\n")
    for ver in df['Version'].unique():
        subset = df[df['Version']==ver]
        times = subset['Time_us'].values
        line = "{:<15s} {:>10.2f} {:>10.2f} {:>10.2f} {:>10.2f} {:>10.2f}".format(
            ver, times.mean(), np.median(times), times.std(), times.min(), times.max()
        )
        print(line)
        f.write(line + "\n")

    # Mann-Whitney U test between OpenSSL versions
    openssl111_times = df[df['Version']=='OpenSSL 1.1.1']['Time_us']
    openssl30_times = df[df['Version']=='OpenSSL 3.0']['Time_us']
    if not openssl111_times.empty and not openssl30_times.empty:
        stat, p_value = mannwhitneyu(openssl111_times, openssl30_times, alternative='two-sided')
        test_line = f"Mann-Whitney U test OpenSSL 1.1.1 vs 3.0: U={stat}, p={p_value:.6f}"
        print(test_line)
        f.write(test_line + "\n")

print(f"\nLibrary statistics saved to {stat_file}")

# -----------------------------
# Boxplot per library
# -----------------------------
plt.figure(figsize=(12,6))
sns.boxplot(x='Library', y='Time_us', data=df)
plt.xticks(rotation=45, ha='right')
plt.ylabel("Encryption Time (µs)")
plt.title("Timing Distribution per Library")
plt.tight_layout()
plt.savefig(os.path.join(figure_dir, "boxplot_library.png"))
plt.close()

# -----------------------------
# Violin plot per version
# -----------------------------
plt.figure(figsize=(8,6))
sns.violinplot(x='Version', y='Time_us', data=df)
plt.ylabel("Encryption Time (µs)")
plt.title("Timing Distribution per OpenSSL Version")
plt.tight_layout()
plt.savefig(os.path.join(figure_dir, "violin_version.png"))
plt.close()

# -----------------------------
# Histogram per version
# -----------------------------
plt.figure(figsize=(10,6))
for ver in df['Version'].unique():
    subset = df[df['Version']==ver]
    sns.histplot(subset['Time_us'], kde=True, bins=30, alpha=0.5, label=ver)
plt.xlabel("Encryption Time (µs)")
plt.ylabel("Count")
plt.title("Histogram of Encryption Times by Version")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(figure_dir, "histogram_versions.png"))
plt.close()

# -----------------------------
# PCA visualization
# -----------------------------
# X = df[['Time_us']].values
# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)
# pca = PCA(n_components=2)
# X_pca = pca.fit_transform(X_scaled)

# plt.figure(figsize=(8,6))
# sns.scatterplot(x=X_pca[:,0], y=X_pca[:,1], hue=df['Version'], style=df['Library'], s=100)
# plt.title("PCA of Timing Data by Version")
# plt.grid(True)
# plt.tight_layout()
# plt.savefig(os.path.join(figure_dir, "pca_versions.png"))
# plt.close()

# print("Analysis complete. Plots and statistics saved to:", figure_dir)

# -----------------------------
# 1D Density Plot
# -----------------------------
plt.figure(figsize=(10,6))
for lib in df['Library'].unique():
    subset = df[df['Library'] == lib]
    sns.kdeplot(subset['Time_us'], label=lib, linewidth=2)

plt.xlabel("Encryption Time (µs)")
plt.ylabel("Density")
plt.title("Kernel Density Estimate of Timing per Library")
plt.legend()
plt.tight_layout()
plt.savefig("kde_library.png")
plt.close()

# -----------------------------
# ECDF Plot
# -----------------------------
plt.figure(figsize=(10,6))
for lib in df['Library'].unique():
    subset = df[df['Library'] == lib]['Time_us']
    ecdf = ECDF(subset)
    plt.plot(ecdf.x, ecdf.y, label=lib)

plt.xlabel("Encryption Time (µs)")
plt.ylabel("ECDF")
plt.title("ECDF of Encryption Timing")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("ecdf_library.png")
plt.close()

# -----------------------------
# Violin Plot + jittered points
# -----------------------------
plt.figure(figsize=(10,6))
sns.violinplot(x='Library', y='Time_us', data=df, inner=None)
sns.stripplot(x='Library', y='Time_us', data=df,
              color='black', size=3, jitter=True, alpha=0.5)
plt.xticks(rotation=45, ha='right')
plt.ylabel("Encryption Time (µs)")
plt.title("Timing Distribution per Library (1D)")
plt.tight_layout()
plt.savefig("violin_strip_library.png")
plt.close()

