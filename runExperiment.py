import os
import shutil
import subprocess

# -------------------------------
# Configuration
# -------------------------------
TIMING_SCRIPT = "timeAnalysis.py"  
DATA_ANALYSIS_SCRIPT = "dataAnalysis.py"  
OUTPUT_DIR = "output"
NUM_RUNS = 5

# -------------------------------
# 1. Clean/create output folder
# -------------------------------
if os.path.exists(OUTPUT_DIR):
    shutil.rmtree(OUTPUT_DIR)
os.makedirs(OUTPUT_DIR)

# -------------------------------
# 2. Run timingAnalysis NUM_RUNS times
# -------------------------------
for i in range(1, NUM_RUNS + 1):
    output_file = os.path.join(OUTPUT_DIR, f"results_{i}.txt")
    print(f"Running timingAnalysis {i}/{NUM_RUNS}, output -> {output_file}")
    subprocess.run(["python", TIMING_SCRIPT, "-o", output_file], check=True)

# -------------------------------
# 3. Call dataAnalysis.py on the output directory
# -------------------------------
print(f"Analyzing all results in {OUTPUT_DIR} ...")
subprocess.run(["python", DATA_ANALYSIS_SCRIPT, OUTPUT_DIR], check=True)
