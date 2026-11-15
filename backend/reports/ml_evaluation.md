# MALGUARD AI — Phase 5A: Random Forest ML Model Audit & Evaluation Report

**Date of Audit**: 2026-11-14 08:25:34 UTC  
**Model Identifier**: `Random Forest PE Malware Classifier v1.0`  
**Model Artifact**: `backend/app/ml/models/random_forest_v1.pkl`  
**Dataset Reference**: `backend/app/ml/data/dataset_malwares.csv` (ClaMP / VirusShare)  
**Feature Count**: 69 Canonical Static PE Features  
**Auditor**: Automated MALGUARD AI Security Audit Suite  

---

## Executive Summary

An audit and held-out empirical evaluation was conducted on the existing MALGUARD AI **Random Forest v1.0** PE classifier.

* **Dataset Authenticity**: The dataset is **genuine** (extracted PE headers from VirusShare malware and clean Windows system binaries), **not synthetic**.
* **Feature Parity**: **100% verified**. All 69 static PE features extracted during real-time inference match the training schema in name, type, and index order.
* **Held-Out Test Performance (Random Split)**:
  * **Accuracy**: **99.01%**
  * **ROC-AUC**: **0.9982**
  * **Malicious Class (Positive = 1)**: Precision: **98.69%**, Recall: **99.91%**, F1-Score: **0.9930**
  * **Benign Class (Negative = 0)**: Precision: **99.79%**, Recall: **96.88%**, F1-Score: **0.9831**
  * **Confusion Matrix**: True Positives (TP): **2,331** | True Negatives (TN): **962** | False Positives (FP): **31** | False Negatives (FN): **2**
  * **False Positive Rate (FPR)**: **3.12%**
  * **False Negative Rate (FNR)**: **0.086%**
* **Critical Findings & Bias Discovered**:
  1. **Compiler/Linker Artifact Bias**: The top 6 features (`MajorLinkerVersion`, `MajorOperatingSystemVersion`, `MajorSubsystemVersion`, `MinorOperatingSystemVersion`, `TimeDateStamp`, `MinorSubsystemVersion`) account for **46.8%** of all decision weight.
  2. **Temporal Domain Shift**: When evaluated across a temporal boundary (pre-2014 vs post-2014), model accuracy drops to **87.62%** and the False Positive Rate on new benign binaries jumps to **49.30%** (Benign F1 drops to 0.5663).
  3. **Probability Calibration**: Uncalibrated leaf voting (`k / 120`). Intermediate confidence percentages overestimate malware likelihood.

---

## 1. Dataset Provenance and Sample Composition

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Dataset Source** | ClaMP / Automated Malware Analysis Repository | Anustup Mukherjee / VirusShare PE corpus |
| **Data Nature** | Genuine PE Headers & Structural Metrics | **Not synthetic**; extracted from real executables |
| **Raw Sample Count** | **19,611** | 14,599 Malware (74.4%) / 5,012 Benign (25.6%) |
| **Identical Feature Duplicates** | **2,984** samples | Removed during preprocessing prior to splitting |
| **Conflicting Label Contradictions** | **4** samples | Same features labeled both benign and malware |
| **Cleaned Dataset Total** | **16,627** unique samples | 11,665 Malware (70.16%) / 4,962 Benign (29.84%) |
| **Class Imbalance** | **2.35 : 1** (Malware to Benign) | No class weights (`class_weight=None`) used |
| **Training Split (80%)** | **13,301** samples | Stratified (9,332 Malware, 3,969 Benign) |
| **Held-Out Test Split (20%)** | **3,326** samples | Stratified (2,333 Malware, 993 Benign) |
| **Random Seed** | `random_state=42` | Strictly deterministic and reproducible |

---

## 2. Feature Schema & Inference Parity Verification

The 69 features are categorized into 6 architectural PE groups:

1. **DOS Header (16 features)**: `e_cblp`, `e_cp`, `e_crlc`, `e_cparhdr`, `e_minalloc`, `e_maxalloc`, `e_ss`, `e_sp`, `e_csum`, `e_ip`, `e_cs`, `e_lfarlc`, `e_ovno`, `e_oemid`, `e_oeminfo`, `e_lfanew`
2. **COFF File Header (7 features)**: `Machine`, `NumberOfSections`, `TimeDateStamp`, `PointerToSymbolTable`, `NumberOfSymbols`, `SizeOfOptionalHeader`, `Characteristics`
3. **Optional Header (28 features)**: `Magic`, `MajorLinkerVersion`, `MinorLinkerVersion`, `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData`, `AddressOfEntryPoint`, `BaseOfCode`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `MajorImageVersion`, `MinorImageVersion`, `MajorSubsystemVersion`, `MinorSubsystemVersion`, `SizeOfHeaders`, `CheckSum`, `SizeOfImage`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve`, `SizeOfHeapCommit`, `LoaderFlags`, `NumberOfRvaAndSizes`
4. **Import Table Suspicious APIs (1 feature)**: `SuspiciousImportFunctions`
5. **Section Structural Metrics (9 features)**: `SuspiciousNameSection`, `SectionsLength`, `SectionMinEntropy`, `SectionMinRawsize`, `SectionMinVirtualsize`, `SectionMaxPhysical`, `SectionMaxVirtual`, `SectionMaxPointerData`, `SectionMaxChar`
6. **Import/Export Directory Metadata (8 features)**: `DirectoryEntryImport`, `DirectoryEntryImportSize`, `DirectoryEntryExport`, `ImageDirectoryEntryExport`, `ImageDirectoryEntryImport`, `ImageDirectoryEntryResource`, `ImageDirectoryEntryException`, `ImageDirectoryEntrySecurity`

**Parity Audit**:
* `FEATURE_NAMES` in `pe_feature_extractor.py` == `feature_schema.json`: **MATCH (1:1)**
* Feature extraction ordering during `ml_service.predict()`: **MATCH (Exact index order)**
* Data Type: `float64` across all 69 features.

---

## 3. Model Architecture & Hyperparameters

* **Estimator**: `sklearn.ensemble.RandomForestClassifier`
* **Number of Trees (`n_estimators`)**: `120`
* **Maximum Tree Depth (`max_depth`)**: `16`
* **Minimum Samples to Split (`min_samples_split`)**: `4`
* **Minimum Samples at Leaf (`min_samples_leaf`)**: `2`
* **Feature Subset Strategy (`max_features`)**: `"sqrt"` (sqrt(69) ≈ 8.3 features per split)
* **Bootstrap**: `True` (with Out-of-Bag scoring: OOB Score = `0.9902`)
* **Serialization**: Joblib compression level 3 (`1.08 MB` on disk)

---

## 4. Empirical Held-Out Test Evaluation

> Positive Class (+): **MALICIOUS** (1)  
> Negative Class (-): **BENIGN** (0)  
> Total Held-Out Samples: **3,326**

### Confusion Matrix
| | Predicted Benign (0) | Predicted Malicious (1) | Total Actual |
| :--- | :---: | :---: | :---: |
| **Actual Benign (0)** | **TN = 962** | **FP = 31** | 993 |
| **Actual Malicious (1)** | **FN = 2** | **TP = 2,331** | 2,333 |
| **Total Predicted** | 964 | 2,362 | 3,326 |

### Performance Metrics
* **Accuracy**: **99.01%** ((TP + TN) / Total)
* **ROC-AUC**: **0.9982**
* **Precision (Malicious)**: **98.69%** (TP / (TP + FP))
* **Recall / True Positive Rate (Malicious)**: **99.91%** (TP / (TP + FN))
* **F1-Score (Malicious)**: **0.9930**
* **Precision (Benign)**: **99.79%** (TN / (TN + FN))
* **Recall / True Negative Rate (Benign)**: **96.88%** (TN / (TN + FP))
* **F1-Score (Benign)**: **0.9831**
* **False Positive Rate (FPR)**: **3.12%** (FP / (FP + TN))
* **False Negative Rate (FNR)**: **0.086%** (FN / (FN + TP))
* **Brier Score**: **0.00912**

---

## 5. Top 10 Most Influential Features

| Rank | Feature Name | PE Category | Feature Importance | Cumulative |
| :---: | :--- | :--- | :---: | :---: |
| 1 | `MajorLinkerVersion` | Optional Header | 0.10159 | 10.16% |
| 2 | `MajorOperatingSystemVersion` | Optional Header | 0.08773 | 18.93% |
| 3 | `MajorSubsystemVersion` | Optional Header | 0.08618 | 27.55% |
| 4 | `MinorOperatingSystemVersion` | Optional Header | 0.08428 | 35.98% |
| 5 | `TimeDateStamp` | COFF File Header | 0.05697 | 41.68% |
| 6 | `MinorSubsystemVersion` | Optional Header | 0.05384 | 47.06% |
| 7 | `SizeOfStackReserve` | Optional Header | 0.05294 | 52.35% |
| 8 | `ImageBase` | Optional Header | 0.05211 | 57.56% |
| 9 | `Subsystem` | Optional Header | 0.04902 | 62.47% |
| 10 | `MinorImageVersion` | Optional Header | 0.03854 | 66.32% |

---

## 6. Critical Findings & Data Leakage Analysis

### Finding 1: Compiler & Header Metadata Bias (Shortcut Learning)
Over **47%** of the model's split decisions rely on linker versions, operating system version requirements, and compilation timestamps.
* Malware authors frequently use older compilation tools, packers (UPX, ASPack), or MinGW/GCC cross-compilers.
* Benign training samples were extracted primarily from official Windows installations compiled with enterprise Microsoft Visual C++ toolchains.
* **Risk**: The model partially learned to detect *compiler toolchains and compilation eras* rather than malicious code behavior.

### Finding 2: Temporal Domain Shift
When evaluated on a strict temporal hold-out split (training on binaries before 2014, evaluating on binaries compiled 2014 or later):
* **Accuracy dropped from 99.01% to 87.62%**.
* **False Positives on benign files spiked from 3.12% to 49.30%**.
* **Benign F1 dropped to 0.5663**.
This confirms that without signature verification, static PE ML models suffer from temporal decay when encountering binaries compiled with newer toolchains.

### Finding 3: Probability Calibration
* The Random Forest outputs raw tree voting proportions (`k / 120`).
* Mid-range probabilities (e.g. 20% to 50%) overestimate malware probability because of the 70% malware training prior and absence of isotonic or sigmoid calibration.
* **Architecture Validation**: The MALGUARD AI policy of reporting probabilities as "statistical model estimates" and requiring official ClamAV confirmation before declaring `NO_THREAT_DETECTED` is justified.

---

## 7. Recommended Next Steps (Phase 5B / 6)

1. **Ablation & Retraining with Bias-Mitigated Feature Schema**:
   * Test training a Random Forest variant that excludes linker version and timestamp fields (`TimeDateStamp`, `MajorLinkerVersion`, `MajorOperatingSystemVersion`), forcing the trees to rely on structural section entropy, API imports, and resource characteristics.
2. **Probability Calibration**:
   * Fit `CalibratedClassifierCV(method='isotonic', cv='prefit')` on held-out calibration samples to align predicted percentages with true posterior probabilities.
3. **Class Weighting**:
   * Apply `class_weight='balanced'` to prevent bias toward the majority malware class.
4. **Preserve Defense-in-Depth**:
   * Keep official ClamAV signature scanning mandatory for all definitive verdicts.
