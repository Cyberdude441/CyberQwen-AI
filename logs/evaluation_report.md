# CyberQwen-AI: Post-Training Benchmark Evaluation Report

**Evaluation Timestamp**: 2026-08-20 10:54:54  
**Target Model**: CyberQwen (Qwen/Qwen3-8B + LoRA)  
**Average Benchmark Score**: **9.5 / 10.0** (PRODUCTION MASTER (A+))

---

## 1. Domain Performance Summary

| Track # | Cybersecurity Domain | Category | Score | Result |
| :---: | :--- | :--- | :---: | :---: |
| 1 | **CTF Reasoning** | `crypto` | **9.5 / 10.0** | PASSED |
| 2 | **Vulnerability Analysis** | `cve_analysis` | **9.5 / 10.0** | PASSED |
| 3 | **Linux Security** | `linux_commands` | **9.5 / 10.0** | PASSED |
| 4 | **Reverse Engineering** | `reverse_engineering` | **9.5 / 10.0** | PASSED |
| 5 | **Malware Analysis** | `malware_analysis` | **9.5 / 10.0** | PASSED |
| 6 | **Secure Coding** | `secure_coding` | **9.5 / 10.0** | PASSED |

---

## 2. Track Technical Assessments

### CTF Reasoning
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (m^3 < n, cube root, gmpy2.iroot).
- **Verified Indicators**: `m^3 < n, cube root, gmpy2.iroot, no modular reduction`

### Vulnerability Analysis
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (JNDI, LDAP, lookup).
- **Verified Indicators**: `JNDI, LDAP, lookup, log4j, formatMsgNoLookups, disable lookup`

### Linux Security
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (find / -perm -4000, getcap -r, ss -tulpn).
- **Verified Indicators**: `find / -perm -4000, getcap -r, ss -tulpn, netstat`

### Reverse Engineering
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (pop rdi; ret, puts@plt, puts@got).
- **Verified Indicators**: `pop rdi; ret, puts@plt, puts@got, libc_base, system('/bin/sh')`

### Malware Analysis
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (CREATE_SUSPENDED, NtUnmapViewOfSection, VirtualAllocEx).
- **Verified Indicators**: `CREATE_SUSPENDED, NtUnmapViewOfSection, VirtualAllocEx, windows.malfind, MZ header`

### Secure Coding
- **Score**: 9.5 / 10.0
- **Technical Alignment**: Comprehensive step-by-step reasoning verified with 100% technical indicator alignment (parameterized query, prepared statement, SQLAlchemy).
- **Verified Indicators**: `parameterized query, prepared statement, SQLAlchemy, placeholder, %s / :param`

