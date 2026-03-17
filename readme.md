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
`Viper` helps catch them **early**, before they reach production.*  

## 🚀 Features
- Scans `.move` source files and `Move.toml` manifests
- Heuristically detects **10+ vulnerability classes**:
  - Incorrect visibility declarations
  - Missing permission/capability validation
  - Unverified calculation/oracle data
  - Late or missing `assert!` checks
  


⚠️ Disclaimer

Viper is not a substitute for:

Formal verification with Move Prover
professional audits
Runtime fuzzing

It’s a first-pass heuristic scanner:
✅ Quick to run
✅ Easy to understand
❌ May report false positives/negatives


