#
# dataAnalysis_old.py
# Runs analysis on collected timing data.
#

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import seaborn as sns
from sklearn.metrics import silhouette_score
from sklearn.cluster import DBSCAN
from scipy.spatial import ConvexHull
import numpy as np
from scipy.stats import f_oneway

# -----------------------------
# Data Analysis Configuration
# -----------------------------
mean_plot_on = False
single_size_on = False
violin_on = False
box_on = False
k_means_on = False
dbscan_on = False

show_plots = False

# -----------------------------
# Read input directory
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
    print(f"Error: {figure_dir} is not a directory")
    sys.exit(1)

# -----------------------------
# Read and parse all results files
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

        # Expecting: Library Operation Size(B) Time_ns
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue

        library = parts[0]
        size = float(parts[1]) if parts[1] != '-' else None
        time_ns = float(parts[2]) if parts[2] != '-' else None
        time_us = time_ns / 1000.0 if time_ns is not None else None

        data.append({
            "Library": library,
            "Size": size,
            "Time_us": time_us
        })

df = pd.DataFrame(data)

if df.empty:
    print("No valid data found in directory.")
    sys.exit(1)

# -----------------------------
# Plot Mean Time vs Message Size
# -----------------------------

if mean_plot_on:
    print("Plotting Mean Time vs Message Size...")
   
    plt.figure(figsize=(10,6))
    for lib in df['Library'].unique():
        lib_data = df[df['Library'] == lib].sort_values('Size')
        plt.plot(lib_data['Size'], lib_data['Time_us'], marker='o', linestyle='none', label=lib)

    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel("Message Size (Bytes)")
    plt.ylabel("Time (µs)")
    plt.title("Encryption Time vs Message Size")
    plt.legend(bbox_to_anchor=(1.05, 1))
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.tight_layout()
    fname = os.path.join(figure_dir, f"mean_encryption_time.png")
    plt.savefig(fname)
    print(f"Saved plot: {fname}")
    if show_plots:
        plt.show()
        plt.close()

# -----------------------------
# Plot for operation vs time
# -----------------------------
if single_size_on:
    TARGET_SIZE = 65536
    print(f"Plotting Encryption Time for Each Library(1 message size: {TARGET_SIZE})...")
    subset = df[(df["Size"] == TARGET_SIZE)]

    # Sort libraries by speed
    subset = subset.sort_values("Time_us")
    plt.figure(figsize=(10,6))
    plt.bar(subset["Library"], subset["Time_us"], color="skyblue", edgecolor="black")
    plt.ylabel("Time (µs)")
    plt.xlabel("Library")
    plt.xticks(rotation=45, ha="right")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.title(f"Encryption Time for Message Size = {TARGET_SIZE} Bytes")

    # Add numeric labels on bars
    for idx, row in subset.iterrows():
        plt.text(idx, row["Time_us"], f"{row['Time_us']:.2f}", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.grid(True, which="both", ls="--", lw=0.5)
    outpath = os.path.join(figure_dir, f"encryption_single_size_{TARGET_SIZE}.png")
    plt.savefig(outpath)
    print(f"Saved plot: {outpath}")
    if show_plots:
        plt.show()
        plt.close()

# -----------------------------
# Violin Plots per Operation - distribution and density visualization
# -----------------------------

if violin_on:
    print("Creating Violin Plots...")
    plt.figure(figsize=(10,6))
    data_to_plot = []
    labels = []

    for lib in df['Library'].unique():
        lib_subset = df[df['Library'] == lib]
        data_to_plot.append(lib_subset['Time_us'].dropna().tolist())
        labels.append(lib)

    plt.violinplot(data_to_plot, showmeans=True, showmedians=True)
    plt.xticks(range(1, len(labels)+1), labels, rotation=45)
    plt.ylabel("Time (µs)")
    plt.title("Violin Plot of Timing for Encryption")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.tight_layout()
    fname = os.path.join(figure_dir, f"violin_encrpytion_time.png")
    plt.savefig(fname)
    print(f"Saved plot: {fname}")
    if show_plots:
        plt.show()
        plt.close()

# -----------------------------
# Compute statistics
# -----------------------------
print("Computing statistics...")
stat_file = os.path.join(figure_dir, "stats.txt")

with open(stat_file, "w") as f:
    f.write("=== Library Statistics ===\n\n")
    header = "{:<20s} {:>12s} {:>12s} {:>12s}".format("Library", "Mean (us)", "Median (us)", "Variance")
    print(header)
    f.write(header + "\n")

    # Per-library statistics
    for lib in df['Library'].unique():
        lib_subset = df[df['Library'] == lib].dropna(subset=['Size','Time_us'])
        times = lib_subset['Time_us'].tolist()

        mean_time = np.mean(times)
        median_time = np.median(times)
        var_time = np.var(times)

        line = "{:<20s} {:>12.2f} {:>12.2f} {:>12.2f}".format(lib, mean_time, median_time, var_time)
        print(line)
        f.write(line + "\n")

    f.write("\n")

    # Correlation between Time_us and Library (encoded)
    library_codes = {lib: i for i, lib in enumerate(df['Library'].unique())}
    df['Library_code'] = df['Library'].map(library_codes)
    corr_time_lib = np.corrcoef(df['Time_us'], df['Library_code'])[0,1]
    corr_line = f"Correlation between Time_us and Library (encoded 0-9): {corr_time_lib:.4f}"
    print(corr_line)
    f.write(corr_line + "\n\n")

    # Mean times per library
    f.write("Mean Time per Library (us):\n")
    mean_times = df.groupby('Library')['Time_us'].mean()
    for lib, mean_val in mean_times.items():
        line = f"{lib:<20s}: {mean_val:.2f}"
        print(line)
        f.write(line + "\n")

    f.write("\n")

    # ANOVA test
    groups = [df[df['Library']==lib]['Time_us'] for lib in df['Library'].unique()]
    F, p = f_oneway(*groups)
    anova_line = f"ANOVA F-statistic: {F:.2f}, p-value: {p:.9f}"
    print(anova_line)
    f.write(anova_line + "\n")

print(f"\nLibrary statistics saved to {stat_file}")

# -----------------------------
# Boxplots per Operation - show distribution for each operation with each library
# -----------------------------

if box_on:
    print("Creating Boxplots...")

    plt.figure(figsize=(10,6))
    box_data = [df[df['Library'] == lib]['Time_us'].dropna().tolist() for lib in df['Library'].unique()]
    labels = df['Library'].unique()
    plt.boxplot(box_data, tick_labels=labels, showmeans=True)
    plt.ylabel("Time (µs)")
    plt.title(f"Boxplot of Timing for Encryption")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.grid(True, which="both", ls="--", lw=0.5)
    fname = os.path.join(figure_dir, "boxplot.png")
    plt.savefig(fname)
    print(f"Saved plot: {fname}")
    if show_plots:
        plt.show()
        plt.close()

# -----------------------------
# K-Means Clustering
# -----------------------------

# feature_df = df[['Library', 'Size', 'Time_us']].dropna()
feature_df = df[df["Size"].isin([65536, 16384])][['Library', 'Size', 'Time_us']].dropna() # Excluding smaller message sizes
if not feature_df.empty:
    X = feature_df[['Size', 'Time_us']].values

    # Standardize features for KMeans
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    n_clusters = 3  # adjust as needed
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    feature_df['cluster'] = kmeans.fit_predict(X_scaled)

    if k_means_on:
        print("K-means cluster analysis...")
        score = silhouette_score(X_scaled, feature_df['cluster'])
        print(f"\nSilhouette Score (cluster quality): {score:.4f}\n")

        plt.figure(figsize=(10, 6))
        sns.scatterplot(data=feature_df, x='Size', y='Time_us', hue='Library', palette='tab20',s=50)
        plt.xlabel('Time (us)')
        plt.ylabel('Variance Time (ns)')
        plt.title('KMeans Clustering of Libraries/Operations')
        plt.grid(True, which="both", ls="--", lw=0.5)
        if show_plots:
            plt.show()
            plt.close()

        # Draw cluster convex hulls
        # for cl in feature_df['cluster'].unique():
        #     pts = feature_df[feature_df['cluster'] == cl][['Size', 'Time_us']].values

        #     if len(pts) >= 3:
        #         hull = ConvexHull(pts)
        #         hull_pts = pts[hull.vertices]
        #         hull_pts = np.vstack([hull_pts, hull_pts[0]])  # close shape

        #         plt.plot(
        #             hull_pts[:, 0], hull_pts[:, 1],
        #             linestyle='--',
        #             linewidth=2,
        #             alpha=0.7,
        #             label=f'Cluster {cl} boundary'
        #         )
        #     else:
        #         # Draw small circle for tiny clusters
        #         x = pts[:, 0].mean()
        #         y = pts[:, 1].mean()
        #         circle = plt.Circle((x, y), radius=0.05 * feature_df['Size'].max(),
        #                             fill=False, ls='--', alpha=0.6)
        #         plt.gca().add_patch(circle)

        # plt.xlabel('Message Size (Bytes)')
        # plt.ylabel('Time (µs)')
        # plt.title('KMeans Clustering on Raw Data\n(Points colored by Library)')
        # plt.grid(True, which="both", ls="--", lw=0.5)
        # plt.legend(title='Cluster')
        # if show_plots:
        #     plt.show()
        #     plt.close()

# -----------------------------
# DBScan Clustering
# -----------------------------

if dbscan_on:
    print("DBScan Cluster analysis...")

    # feature_df = df[['Library', 'Size', 'Time_us']].dropna() 
    feature_df = df[df["Size"].isin([1024, 16384, 65536])][['Library', 'Size', 'Time_us']].dropna()
    scaler = StandardScaler()
    X_raw = feature_df[['Size', 'Time_us']].values
    X_scaled = scaler.fit_transform(X_raw)

    # DBSCAN parameters
    eps_value = 0.4
    min_samples_value = 20

    # Run DBSCAN on scaled features
    dbscan = DBSCAN(eps=eps_value, min_samples=min_samples_value)
    feature_df['dbscan_cluster'] = dbscan.fit_predict(X_scaled)

    # Count clusters (DBSCAN labels -1 as noise)
    unique_labels = set(feature_df['dbscan_cluster'])
    print(f"DBSCAN clusters found (including noise = -1): {unique_labels}")

    num_clusters = len([label for label in unique_labels if label != -1])
    if num_clusters > 1:
        score = silhouette_score(X_scaled, feature_df['dbscan_cluster'])
        print(f"Silhouette Score for DBSCAN clustering: {score:.4f}")
    else:
        print("Silhouette Score not available (DBSCAN found <=1 cluster)")

    # -------------------------------
    # Plot 1: Colored by Library
    # -------------------------------
    plt.figure(figsize=(10,6))
    sns.scatterplot(data=feature_df,x='Size',y='Time_us',hue='Library',palette='tab20',s=100)
    plt.xlabel("Message Size (Bytes)")
    plt.ylabel("Time (µs)")
    plt.title(f"DBSCAN Data Points Colored by Library")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.legend(bbox_to_anchor=(1.05, 1), title="Library")
    plt.xscale('log')
    plt.yscale('log')
    plt.tight_layout()
    outpath_lib = os.path.join(figure_dir, "dbscan_points_by_library.png")
    plt.savefig(outpath_lib)
    print(f"Saved Library-colored plot: {outpath_lib}")
    if show_plots:
        plt.show()
    plt.close()

    # -------------------------------
    # Plot 2: Colored by DBSCAN Cluster
    # -------------------------------
    plt.figure(figsize=(10,6))
    sns.scatterplot(data=feature_df,x='Size',y='Time_us',hue='dbscan_cluster', palette='tab10',s=100)
    plt.xlabel("Message Size (Bytes)")
    plt.ylabel("Time (µs)")
    plt.title(f"DBSCAN Clustering (eps={eps_value}, min_samples={min_samples_value})")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.xscale('log')
    plt.yscale('log')
    plt.legend(bbox_to_anchor=(1.05, 1), title="Cluster ID (-1 = noise)")
    plt.tight_layout()
    outpath_cluster = os.path.join(figure_dir, "dbscan_points_by_cluster.png")
    plt.savefig(outpath_cluster)
    print(f"Saved Cluster-colored plot: {outpath_cluster}")
    if show_plots:
        plt.show()
        plt.close()

    # removing noisy data
    # features_no_noise = feature_df[feature_df['dbscan_cluster'] != -1]
    # plt.figure(figsize=(10,6))
    # sns.scatterplot(data=features_no_noise,x='Size', y='Time_us',hue='dbscan_cluster',palette='tab10',s=200)

    # # Add labels only for non-noise points
    # for i, row in features_no_noise.iterrows():
    #     plt.text(row['mean'], row['var'], row['Library'], fontsize=9, ha='right')

    # plt.xlabel("Mean Time (ns)")
    # plt.ylabel("Variance (ns²)")
    # plt.title(f"DBSCAN Clusters Only (Noise Removed)")
    # plt.grid(True, which="both", ls="--", lw=0.5)
    # plt.legend(title="Cluster ID")
    # # plt.tight_layout()

    # outpath_clean = os.path.join(figure_dir, f"dbscan_clusters_no_noise.png")
    # plt.savefig(outpath_clean)
    # print(f"Saved DBSCAN cluster plot without noise: {outpath_clean}")

    # plt.show()
    # plt.close()


print("Analysis complete.")
