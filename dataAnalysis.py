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

# -----------------------------
# Data Analysis Configuration
# -----------------------------
mean_plot_on = False
single_size_on = False
violin_on = False
box_on = False
k_means_on = False
dbscan_on = True

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
        if len(parts) < 4:
            continue

        library = parts[0]
        operation = parts[1]
        size = float(parts[2]) if parts[2] != '-' else None
        time_ns = float(parts[3]) if parts[3] != '-' else None
        time_us = time_ns / 1000.0 if time_ns is not None else None

        data.append({
            "Library": library,
            "Operation": operation,
            "Size": size,
            "Time_us": time_us
        })

df = pd.DataFrame(data)

if df.empty:
    print("No valid data found in directory.")
    sys.exit(1)

# -----------------------------
# Plot Mean Time vs Message Size for encrypt/decrypt
# -----------------------------

if mean_plot_on:
    print("Plotting Mean Time vs Message Size for Encrypt/Decrypt...")
    for op in ['encrypt', 'decrypt']:
        subset = df[df['Operation'] == op]
        if subset.empty:
            continue

        plt.figure(figsize=(10,6))
        for lib in subset['Library'].unique():
            lib_data = subset[subset['Library'] == lib].sort_values('Size')
            plt.plot(lib_data['Size'], lib_data['Time_us'], marker='o', label=lib)

        plt.xscale('log')
        plt.yscale('log')
        plt.xlabel("Message Size (Bytes)")
        plt.ylabel("Time (µs)")
        plt.title(f"{op.capitalize()} Time vs Message Size")
        plt.legend(bbox_to_anchor=(1.05, 1))
        plt.grid(True, which="both", ls="--", lw=0.5)
        plt.tight_layout()
        fname = os.path.join(figure_dir, f"{op}_time.png")
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
    print(f"Plotting Encrypt/Decrypt Time for Each Operation (1 message size: {TARGET_SIZE})...")
    for op in ["encrypt", "decrypt"]:
        subset = df[(df["Operation"] == op) & (df["Library"] != "3DES-CBC") & (df["Size"] == TARGET_SIZE)]
        if subset.empty:
            continue

        # Sort libraries by speed
        subset = subset.sort_values("Time_us")
        plt.figure(figsize=(10,6))
        plt.bar(subset["Library"], subset["Time_us"], color="skyblue", edgecolor="black")
        plt.ylabel("Time (µs)")
        plt.xlabel("Library")
        plt.xticks(rotation=45, ha="right")
        plt.grid(True, which="both", ls="--", lw=0.5)
        plt.title(f"{op.capitalize()} Time for Message Size = {TARGET_SIZE} Bytes")

        # Add numeric labels on bars
        for idx, row in subset.iterrows():
            plt.text(idx, row["Time_us"], f"{row['Time_us']:.2f}", ha="center", va="bottom", fontsize=9)
        plt.tight_layout()
        plt.grid(True, which="both", ls="--", lw=0.5)
        outpath = os.path.join(figure_dir, f"{op}_single_size_{TARGET_SIZE}.png")
        plt.savefig(outpath)
        print(f"Saved plot: {outpath}")
        if show_plots:
            plt.show()
            plt.close()

# -----------------------------
# Violin Plots per Operation - distribution and density visualization
# -----------------------------

if violin_on:
    print("Plotting violin plots per operation...")
    for op in df['Operation'].unique():
        subset = df[df['Operation'] == op]
        if subset.empty:
            continue

        plt.figure(figsize=(10,6))
        data_to_plot = []
        labels = []

        for lib in subset['Library'].unique():
            lib_subset = subset[subset['Library'] == lib]
            data_to_plot.append(lib_subset['Time_us'].dropna().tolist())
            labels.append(lib)

        plt.violinplot(data_to_plot, showmeans=True, showmedians=True)
        plt.xticks(range(1, len(labels)+1), labels, rotation=45)
        plt.ylabel("Time (µs)")
        plt.title(f"Violin Plot of Timing for {op}")
        plt.grid(True, which="both", ls="--", lw=0.5)
        plt.tight_layout()
        fname = os.path.join(figure_dir, f"violin_{op}.png")
        plt.savefig(fname)
        print(f"Saved plot: {fname}")
        if show_plots:
            plt.show()
            plt.close()

# -----------------------------
# Boxplots per Operation - show distribution for each operation with each library
# -----------------------------

if box_on:
    print("Plotting Boxplots per operation...")
    for op in df['Operation'].unique():
        subset = df[df['Operation'] == op]
        if subset.empty:
            continue

        plt.figure(figsize=(10,6))
        box_data = [subset[subset['Library'] == lib]['Time_us'].dropna().tolist() for lib in subset['Library'].unique()]
        labels = subset['Library'].unique()
        plt.boxplot(box_data, labels=labels, showmeans=True)
        plt.ylabel("Time (µs)")
        plt.title(f"Boxplot of Timing for {op}")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.grid(True, which="both", ls="--", lw=0.5)
        fname = os.path.join(figure_dir, f"boxplot_{op}.png")
        plt.savefig(fname)
        print(f"Saved plot: {fname}")
        if show_plots:
            plt.show()
            plt.close()

# -----------------------------
# K-Means Clustering
# -----------------------------

if True:
    feature_df = df[['Library', 'Size', 'Time_us']].dropna()
    # feature_df = df[df["Size"].isin([65536, 16384, 1024])][['Library', 'Size', 'Time_us']].dropna() # Excluding smaller message sizes
    if not feature_df.empty:
        # Keep the library labels separate
        libraries = feature_df['Library'].values
        X = feature_df[['Size', 'Time_us']].values

    if not feature_df.empty:
        features = df.groupby(['Library', 'Operation'])['Time_us'].agg(['mean', 'var', 'min', 'max', 'std']).reset_index()
        features = features.fillna(0)
        # Standardize features for KMeans
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(features[['mean', 'var', 'min', 'max','std']])

        n_clusters = 3  # adjust as needed
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        features['cluster'] = kmeans.fit_predict(X_scaled)

        if k_means_on:
            print("K-means cluster analysis...")
            score = silhouette_score(X_scaled, features['cluster'])
            print(f"\nSilhouette Score (cluster quality): {score:.4f}\n")

            plt.scatter(features['mean'], features['var'], c=features['cluster'], cmap='viridis')
            plt.xlabel('Mean Time (ns)')
            plt.ylabel('Variance Time (ns)')
            plt.title('KMeans Clustering of Libraries/Operations')
            plt.grid(True, which="both", ls="--", lw=0.5)
            if show_plots:
                plt.show()
                plt.close()

            plt.figure(figsize=(10,6))
            sns.scatterplot(data=features, x='mean', y='var', hue='cluster', palette='Set2', s=200)

            for i, row in features.iterrows():
                plt.text(row['mean'], row['var'], row['Library'], fontsize=9, ha='right')

            plt.xlabel('Mean Time (ns)')
            plt.ylabel('Variance (ns²)')
            plt.title('Library Clustering Based on Performance Metrics')
            plt.grid(True, which="both", ls="--", lw=0.5)
            plt.legend(title='Cluster')
            if show_plots:
                plt.show()
                plt.close()

# -----------------------------
# DBScan Clustering
# -----------------------------
if dbscan_on:
    print("DBScan Cluster analysis...")
    # DBSCAN parameters 
    eps_value = 0.4
    min_samples_value = 5

    dbscan = DBSCAN(eps=eps_value, min_samples=min_samples_value)
    features['dbscan_cluster'] = dbscan.fit_predict(X_scaled)

    # Count clusters (DBSCAN labels -1 as noise)
    unique_labels = set(features['dbscan_cluster'])
    print(f"DBSCAN clusters found (including noise = -1): {unique_labels}")

    num_clusters = len([label for label in unique_labels if label != -1])
    if num_clusters > 1:
        score = silhouette_score(X_scaled, features['dbscan_cluster'])
        print(f"Silhouette Score for DBSCAN clustering: {score:.4f}")
    else:
        print("Silhouette Score not available (DBSCAN found <=1 cluster)")

    # Plot DBSCAN results
    plt.figure(figsize=(10,6))
    sns.scatterplot(data=features,x='mean',y='var',hue='dbscan_cluster',palette='tab10',s=200)

    # Add labels (library names)
    for i, row in features.iterrows():
        plt.text(row['mean'], row['var'], row['Library'], fontsize=9, ha='right')

    plt.xlabel("Mean Time (ns)")
    plt.ylabel("Variance (ns²)")
    plt.title(f"DBSCAN Clustering (eps={eps_value}, min_samples={min_samples_value})")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.legend(title="Cluster ID (-1 = noise)")
    plt.tight_layout()
    outpath = os.path.join(figure_dir, f"dbscan_clusters.png")
    plt.savefig(outpath) 
    print(f"Saved DBSCAN cluster plot: {outpath}")
    if show_plots:
        plt.show()
        plt.close()

    # removing noisy data
    features_no_noise = features[features['dbscan_cluster'] != -1]
    plt.figure(figsize=(10,6))
    sns.scatterplot(data=features_no_noise,x='mean', y='var',hue='dbscan_cluster',palette='tab10',s=200)

    # Add labels only for non-noise points
    for i, row in features_no_noise.iterrows():
        plt.text(row['mean'], row['var'], row['Library'], fontsize=9, ha='right')

    plt.xlabel("Mean Time (ns)")
    plt.ylabel("Variance (ns²)")
    plt.title(f"DBSCAN Clusters Only (Noise Removed)")
    plt.grid(True, which="both", ls="--", lw=0.5)
    plt.legend(title="Cluster ID")
    plt.tight_layout()

    outpath_clean = os.path.join(figure_dir, f"dbscan_clusters_no_noise.png")
    plt.savefig(outpath_clean)
    print(f"Saved DBSCAN cluster plot without noise: {outpath_clean}")

    plt.show()
    plt.close()


print("Analysis complete.")