# ECE595CryptoFinalProject

This project performs a timing analysis of various crpytographic libraries focusing on AES128-GCM:
- OpenSSL v1.1.1
- OpenSSL v3.0
- LibreSSL
- BoringSSL 

This setup allows precise, repeatable timing measurements of encryption operations across different cryptographic libraries, isolating implementation-dependent performance differences.

The python script `timeAnalysis.py` runs the various libraries AES128-GCM encrpytion implementation and measures the time it takes using time.perf_counter_ns(). Right now the code uses a fixed message size of 1,024 bytes to be encrypted. The encryption timing measurements are performed by a small C program that executes AES-128-GCM using a randomly generated key, IV, and plaintext. A Python wrapper in `timeAnalysis.py` runs this in executable repeatedly and measures the time of each run using high-resolution timers, while an initial warmup() phase ensures caches and library initialization do not skew results. 

The python script `dataAnalysis.py` runs on the output from `timeAnalysis.py` and creates plots and calculates various statistics on the distribution of measurements.

The python script `runExperiment` runs the above two files.