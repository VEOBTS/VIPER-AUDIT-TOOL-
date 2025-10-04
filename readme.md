# 🐍 Viper >> Automated Move Auditor 
**A lightweight static analyzer for Sui Move smart contracts**  
Viper scans `.move` modules and `Move.toml` packages for common security pitfalls.  
It generates **TXT** or **CSV** reports with flagged vulnerabilities under clear headers

## ✨ Why Viper?
The **Move language** (used in **Sui**) was designed with **resource safety and formal verification** in mind.  
Its strong typing, *linear resource model*, and its integration with **Move Prover** make it one of the most secure smart contract languages.

But… 👇  
Even with these protections, **developers can still shoot themselves in the foot**:
- Using `public` where only `private` should be allowed
- Missing **capability checks** (`TreasuryCap`, `AdminCap`)
- Forgetting to enforce **singleton initialization**
- Misusing **dynamic fields** or `object::delete` without ownership checks
- Poor **assert placement** leading to exploitable state changes

These are not flaws of Move itself, but **developer mistakes** that attackers can exploit.  
`Viper` helps catch them **early**, before they reach production.

## 📚 Vulnerability Sources
The scanning rules are inspired by real research, CVEs, and auditing primers, including:
- [SlowMist Sui Move Smart Contract Auditing Primer](https://github.com/slowmist/Sui-MOVE-Smart-Contract-Auditing-Primer)  
- [Sui Security Best Practices](https://sui.io/security)  
- [MoveBit Research on Sui Objects](https://movebit.xyz/blog/post/Sui-Objects-Security-Principles-and-Best-Practices.html)  
- Known exploit classes reported in **Sui/Solana-style ecosystems**  

## 🚀 Features
- Scans `.move` source files and `Move.toml` manifests
- Heuristically detects **10+ vulnerability classes**:
  - Incorrect visibility declarations
  - Missing permission/capability validation
  - Unverified calculation/oracle data
  - Late or missing `assert!` checks
- **Offline by default** → deterministic scans  
- Optional `--online` flag → fetches community advisories for context  
- Outputs neat **TXT** report (ASCII banner + sections)  
- Optional **CSV export** for spreadsheet workflows  

