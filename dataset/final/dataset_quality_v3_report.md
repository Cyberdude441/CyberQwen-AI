# CyberQwen-AI: Master Dataset Quality & Deduplication Audit Report (v3)

**Audit Timestamp**: 2026-08-20 12:54:17  
**Target Model**: CyberQwen (Qwen3-8B QLoRA)  
**Production Files**: `dataset/final/train_v3.jsonl` & `dataset/final/validation_v3.jsonl`  
**Readiness Status**: **READY FOR PRODUCTION TRAINING**

---

## 1. Executive Quality & Deduplication Metrics

| Metric | Raw / v2 Value | Cleaned v3 Value | Status |
| :--- | :---: | :---: | :--- |
| **Harvested Raw Samples** | 5,302 | - | Complete Corpus Sweep |
| **Exact Duplicates Removed** | - | **2,619** | Deterministic SHA-256 Hashing |
| **Near Duplicates Filtered** | - | **149** | Jaccard Token Cosine $\ge 0.92$ |
| **Total Clean Unique Samples** | 2,500 | **2,534** | 100% Distinct Records |
| **Train Set (`train_v3.jsonl`)** | 2,250 | **2,282** | 0 Internal Duplicates |
| **Val Set (`validation_v3.jsonl`)** | 250 | **252** | 0 Internal Duplicates |
| **Cross-Split Data Leakage** | 0 | **0 samples** | **100% Strict Split Isolation** |
| **Corrupted JSONL Records** | 0 | **0 records** | 100% Valid ChatML Syntax |

---

## 2. Technical Difficulty Distribution (v3)

| Difficulty Tier | Train Count | Train % | Val Count | Val % | Total Unique | Total % | Target Alignment |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Beginner** | 658 | 28.8% | 73 | 29.0% | **731** | **28.8%** | Aligned |
| **Intermediate** | 1,012 | 44.3% | 112 | 44.4% | **1,124** | **44.4%** | Aligned |
| **Advanced** | 486 | 21.3% | 53 | 21.0% | **539** | **21.3%** | Aligned |
| **Expert** | 126 | 5.5% | 14 | 5.6% | **140** | **5.5%** | Aligned |
| **Total** | **2,282** | 100% | **252** | 100% | **2,534** | 100% | Optimal |

---

## 3. Category Breakdown across Clean Corpus

| Category | Count | Percentage |
| :--- | :---: | :---: |
| **vulnerabilities** | 1,529 | 60.3% |
| **threat_intelligence** | 709 | 28.0% |
| **cybersecurity** | 287 | 11.3% |
| **security_corpus** | 3 | 0.1% |
| **malware** | 3 | 0.1% |
| **web** | 1 | 0.0% |
| **pwn** | 1 | 0.0% |
| **crypto** | 1 | 0.0% |

---

## 4. Deduplication Methodology & Examples

1. **Exact Content Deduplication**: SHA-256 hash computed on normalized `user` + `assistant` dialogue text.
2. **Conservative Near-Duplicate Filtering**: Jaccard similarity index computed over extracted token shingles ($N=3$) with a high threshold (0.92) to eliminate templated redundancies without removing unique CVE entries.
3. **Zero-Leakage Stratified Splitting**: 90/10 train-validation assignment performed per-difficulty tier to guarantee identical distributions across splits with strictly disjoint hash sets.

