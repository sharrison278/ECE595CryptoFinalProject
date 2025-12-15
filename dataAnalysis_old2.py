#
# dataAnalysis_old2.py
# Runs analysis on collected timing data and compares OpenSSL versions.
#

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy.stats import f_oneway, mannwhitneyu
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans, DBSCAN

# -----------------------------
# Configuration
# -----------------------------
mean_plot_on = True
single_size_on = True
violin_on = False
box_on = False
k_means_on = False
dbscan_on = False
show_plots = False

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
if not os.path.isdir(figure_dir):
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

        # Everything except the last 2 parts is the library name
        library = " ".join(parts[:-2])
        size = float(parts[-2]) if parts[-2] != '-' else None
        time_ns = float(parts[-1]) if parts[-1] != '-' else None
        time_us = time_ns / 1000.0 if time_ns is not None else None

        data.append({
            "Library": library,
            "Size": size,
            "Time_us": time_us
        })

df = pd.DataFrame(data)
if df.empty:
    print("No valid data found.")
    sys.exit(1)

# -----------------------------
# Add normalized timing per byte
# -----------------------------
df['Time_us_per_byte'] = df['Time_us'] / df['Size']

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
# Compute statistics per library and version
# -----------------------------
stat_file = os.path.join(figure_dir, "stats.txt")
with open(stat_file, "w") as f:
    f.write("=== Library Statistics ===\n\n")
    header = "{:<20s} {:>12s} {:>12s} {:>12s}".format("Library", "Mean(us)", "Median(us)", "Variance")
    print(header)
    f.write(header + "\n")

    for lib in df['Library'].unique():
        subset = df[df['Library']==lib].dropna(subset=['Time_us'])
        times = subset['Time_us'].tolist()
        mean_time = np.mean(times)
        median_time = np.median(times)
        var_time = np.var(times)
        line = "{:<20s} {:>12.2f} {:>12.2f} {:>12.2f}".format(lib, mean_time, median_time, var_time)
        print(line)
        f.write(line + "\n")
    f.write("\n")

    # Per-version statistics
    f.write("=== OpenSSL Version Statistics ===\n")
    for ver in df['Version'].unique():
        subset = df[df['Version']==ver].dropna(subset=['Time_us'])
        times = subset['Time_us'].tolist()
        mean_time = np.mean(times)
        median_time = np.median(times)
        var_time = np.var(times)
        line = "{:<15s} Mean: {:>10.2f}, Median: {:>10.2f}, Var: {:>10.2f}".format(ver, mean_time, median_time, var_time)
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
# Plot median ± std vs message size per version
# -----------------------------
version_stats = df.groupby(['Version','Size']).agg(
    median_time=('Time_us','median'),
    mean_time=('Time_us','mean'),
    std_time=('Time_us','std')
).reset_index()

plt.figure(figsize=(10,6))
for ver in df['Version'].unique():
    subset = version_stats[version_stats['Version']==ver]
    plt.plot(subset['Size'], subset['median_time'], marker='o', label=f"{ver} median")
    plt.fill_between(subset['Size'],
                     subset['median_time'] - subset['std_time'],
                     subset['median_time'] + subset['std_time'],
                     alpha=0.2)
plt.xscale('log')
plt.yscale('log')
plt.xlabel("Message Size (Bytes)")
plt.ylabel("Time (µs)")
plt.title("Median Encryption Time ± Std by OpenSSL Version")
plt.legend()
plt.grid(True, which="both", ls="--", lw=0.5)
plt.tight_layout()
fname = os.path.join(figure_dir, "openssl_version_comparison.png")
plt.savefig(fname)
print(f"Saved plot: {fname}")
if show_plots:
    plt.show()
plt.close()

# -----------------------------
# Optional: PCA to visualize clustering by version
# -----------------------------
feature_df = df[['Size','Time_us','Version','Library']].dropna()
X = feature_df[['Size','Time_us']].values
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

plt.figure(figsize=(8,6))
sns.scatterplot(x=X_pca[:,0], y=X_pca[:,1], hue=feature_df['Version'], style=feature_df['Library'], s=100)
plt.title("PCA of Timing Data by Version")
plt.grid(True)
plt.tight_layout()
fname = os.path.join(figure_dir, "pca_versions.png")
plt.savefig(fname)
print(f"Saved PCA plot: {fname}")
if show_plots:
    plt.show()
plt.close()

print("Analysis complete.")
