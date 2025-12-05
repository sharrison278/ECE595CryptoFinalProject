import os
import shutil
import subprocess

# -------------------------------
# Configuration
# -------------------------------
TIMING_SCRIPT = "timeAnalysis.py"  
DATA_ANALYSIS_SCRIPT = "dataAnalysis.py"  
OUTPUT_DIR = "output"
PLOTS_DIR = "plots"
NUM_RUNS = 100

# -------------------------------
# Clean/create output folder
# -------------------------------
if os.path.exists(OUTPUT_DIR):
    shutil.rmtree(OUTPUT_DIR)
os.makedirs(OUTPUT_DIR)

# -------------------------------
# Run timingAnalysis NUM_RUNS times
# -------------------------------
for i in range(1, NUM_RUNS + 1):
    output_file = os.path.join(OUTPUT_DIR, f"results_{i}.txt")
    print(f"Running timingAnalysis {i}/{NUM_RUNS}, output -> {output_file}")
    subprocess.run(["python3", TIMING_SCRIPT, "-o", output_file], check=True)

# -------------------------------
# Call dataAnalysis.py on the output directory
# -------------------------------
print(f"Analyzing all results in {OUTPUT_DIR} ...")
subprocess.run(["python3", DATA_ANALYSIS_SCRIPT, OUTPUT_DIR, PLOTS_DIR], check=True)
