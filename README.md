# Energy-Resistant Cryptography (ERC)

## TL;DR

1. **What It Is**  
   - **Energy-Resistant Cryptography** is an encryption system where **decryption intentionally costs significant computational work** (and thus energy).  
   - It goes beyond normal “hard” math problems by **embedding proof-of-work, memory-hard key derivation, and time-lock puzzles** directly into decryption.  
   - Attackers trying to brute-force must **pay an enormous energy cost** per key attempt, making large-scale key guessing infeasible.

2. **How It Works**  
   - Uses **AES-256** for the actual encryption.  
   - **Argon2** memory-hard KDF so that each key guess requires large RAM + CPU usage.  
   - **Proof-of-Work** puzzle (like Bitcoin’s mining) to force hashing for each decryption attempt.  
   - **Time-Lock** puzzle (sequential hash chain) to enforce a *minimum real time* for each attempt.  
   - All these steps drastically **raise the cost** of brute-forcing the decryption key.

3. **How to Use It**  
   - **Python Proof of Concept**:  
     - Install requirements (`pycryptodome`, `argon2-cffi`)  
     - Run `example.py` to see how encryption & decryption work with user-defined parameters.  
   - **C++ Production Tool**:  
     - Requires **OpenSSL** and **Argon2** libraries.  
     - Compile `erc.cpp` (example: `g++ -std=c++17 -O2 erc.cpp -lssl -lcrypto -largon2 -pthread -o erc`).  
     - Run `./erc --encrypt -i <file> -o <out> -p <pass> --pow <bits> --argon-mem <MB> ...`  

4. **How It Can Be Used**  
   - **High-value data protection**: If you want to ensure that brute-force attempts are prohibitively expensive.  
   - **Key storage**: Protect a master key (like a root certificate or nuclear code) with an enforced energy cost.  
   - **Long-term or offline data**: Even future quantum or advanced computers still pay a thermodynamic price to brute force.  

That’s the quick overview. **Read on** for a deep dive into theory, code structure, usage examples, and more.

---

# Table of Contents

1. [Conceptual Overview](#conceptual-overview)  
2. [Codebase Structure](#codebase-structure)  
3. [Python Proof-of-Concept](#python-proof-of-concept)  
   1. [Installation & Requirements](#installation--requirements)  
   2. [Quick Start](#quick-start)  
   3. [Detailed Python Usage](#detailed-python-usage)  
4. [C++ Production Implementation](#c-production-implementation)  
   1. [Dependencies](#dependencies)  
   2. [Building & Installation](#building--installation)  
   3. [Usage & Examples](#usage--examples)  
5. [Security Considerations](#security-considerations)  
6. [Performance Tuning](#performance-tuning)  
7. [Roadmap & Future Directions](#roadmap--future-directions)  
8. [License & Disclaimer](#license--disclaimer)

---

## 1. Conceptual Overview

Energy-Resistant Cryptography (ERC) aims to make unauthorized **decryption** of data so expensive in terms of computational **energy** that large-scale brute-force attempts become impractical. Whereas traditional cryptosystems rely primarily on mathematical hardness (e.g., factoring, discrete logs), ERC adds *physical resource costs* (energy/time/thermodynamics) to the equation.

**Key Ideas**:

- **Memory-Hard Key Derivation (Argon2)**: Argon2 forces large memory usage and CPU cycles, so each password/key guess is expensive.  
- **Proof-of-Work (PoW)**: Similar to Bitcoin mining, a puzzle must be solved (finding a nonce that makes the hash meet a difficulty target), which requires real CPU time.  
- **Time-Lock Puzzle**: A sequential computation (cannot be parallelized) that introduces a forced delay.  
- **AES-256 Encryption**: Actual data encryption is done with AES-256. The puzzle ensures you can’t even *try* decrypting unless you expend the required energy or time first.

### Why “Energy-Resistant”?

This approach leverages **Landauer’s Principle** and other physical constraints. Each bit-flip requires some nonzero amount of energy. By forcing large computations or memory usage, we tie the security to real-world energy costs, not just algorithmic complexity. This is especially relevant in a future where:

- Quantum computers might break conventional math-based hardness.  
- Attackers have massive parallel hardware but still pay for energy.  
- We want security that is robust even against hypothetical supercomputers, as they cannot cheat physics.

---

## 2. Codebase Structure

This repository contains multiple files and directories:

```
.
├── Docs/
│   ├── Main.md            (Conceptual background overview)
│   └── ProofofConcept.md  (Detailed Python proof-of-concept explanation)
├── production/
│   ├── README.md          (C++ usage instructions, summarized)
│   └── erc.cpp            (Main C++ source for production-level CLI tool)
├── src/
│   ├── energy_resistant_crypto/
│   │   ├── aes.py         (AES-256 CBC streaming encryption)
│   │   ├── binary_format.py (Reading/writing the custom encrypted file format)
│   │   ├── cli.py         (Command-line interface wrapper in Python)
│   │   ├── kdf.py         (Argon2-based key derivation functions)
│   │   ├── main.py        (High-level Python encryption/decryption routines)
│   │   ├── pow.py         (Proof-of-Work puzzle logic)
│   │   ├── timelock.py    (Time-lock sequential hash chain logic)
│   │   └── __init__.py
│   ├── example.py         (Sample usage of Python library)
│   └── ...
├── requirements.txt       (Python dependencies)
├── setup.py               (Python packaging config)
└── ...
```

### Key Components

- **Python**:
  - **`example.py`**: Shows how to encrypt/decrypt with progress updates.  
  - **`main.py`**: Central location for combining PoW + Argon2 + Time-Lock + AES.  
  - **`pow.py`, `timelock.py`, `kdf.py`, `aes.py`**: Implement the respective puzzle/KDF/crypto details.

- **C++**:
  - **`erc.cpp`**: Standalone command-line utility that does the same (AES + PoW + Argon2 + Time-Lock).  
  - **`production/README.md`**: Original instructions for building on various platforms.

---

## 3. Python Proof-of-Concept

### 3.1 Installation & Requirements

1. **Python 3.7+**  
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
   or
   ```bash
   pip install pycryptodome argon2-cffi
   ```

3. (Optional) If you want to install as a package:

   ```bash
   python setup.py install
   ```

   This provides an `erc` command-line tool entry point (`energy_resistant_crypto.cli:main_cli`) if configured.

### 3.2 Quick Start

**Encrypting a string in Python**:

```python
from energy_resistant_crypto.main import encrypt, decrypt, EncryptionParameters

message = b"Hello Energy-Resistant World!"
password = "MyVerySecurePassword"
params = EncryptionParameters(
    pow_difficulty_bits=16,  # 16 leading zero bits in PoW
    argon_mem_cost_kb=65536, # 64 MB Argon2 memory
    argon_time_cost=3,
    timelock_iterations=1000000
)

# Encrypt
encrypted_data = encrypt(message, password, params)

# Decrypt
decrypted_data, stats = decrypt(encrypted_data, password)
assert decrypted_data == message
```

### 3.3 Detailed Python Usage

The main entry points:

1. **`encrypt_stream(in_stream, out_stream, password, params)`**  
   - Reads plaintext from `in_stream`, writes encrypted bytes to `out_stream`.  
   - Embeds a header containing salt, IV, puzzle difficulty, etc.

2. **`decrypt_stream(in_stream, out_stream, password)`**  
   - Reads the header (salt, IV, puzzle config), does PoW if required, Argon2 to derive the key, time-lock chain, then decrypts.

You can also:

- **Adjust Argon2** parameters (`argon_mem_cost_kb`, `argon_time_cost`, `argon_parallelism`) to control memory/CPU load.  
- **Adjust PoW difficulty** bits to control how many hashes the solver must attempt.  
- **Adjust time-lock** iterations to add sequential (non-parallelizable) compute time.

**Example with `example.py`:**

```bash
python src/example.py
```

This will:
- Encrypt a sample message with moderate default parameters (PoW=16 bits, Argon2 with 64 MB, etc.)  
- Write `encrypted_message.json`  
- Then read it, decrypt it, and show timing stats.  

Expect a few seconds of heavy CPU usage on standard hardware, illustrating the resource-intensive nature of decryption.

---

## 4. C++ Production Implementation

For more performance-oriented or system-level usage, there is a **single-file C++ program** (`erc.cpp`) that implements the same ideas:

### 4.1 Dependencies

1. **OpenSSL** ≥ 1.1.1: For AES-256 encryption and SHA-256.  
2. **Argon2 library**: For memory-hard key derivation.  
3. **C++17** compiler and **pthread** for multi-threading.  

Examples:

- **Debian/Ubuntu**: `sudo apt-get install libssl-dev libargon2-dev build-essential`  
- **Fedora**: `sudo dnf install openssl-devel argon2-devel`  
- **macOS**: `brew install openssl argon2`  
- **Windows** + **vcpkg**: `vcpkg install openssl argon2`

### 4.2 Building & Installation

**Linux/macOS**:

```bash
g++ -std=c++17 -O2 -o erc erc.cpp -lssl -lcrypto -largon2 -pthread
```

Adjust `-I`/`-L` paths as needed if libraries are in nonstandard locations.

**Windows** (MSVC + vcpkg):

```bash
cl /std:c++17 /O2 erc.cpp ^
  /I"%VCPKG_ROOT%\installed\x64-windows\include" ^
  /link /LIBPATH:"%VCPKG_ROOT%\installed\x64-windows\lib" libssl.lib libcrypto.lib argon2.lib
```

### 4.3 Usage & Examples

Once built, usage:

```bash
./erc --encrypt -i <input> -o <output> -p <password> [options]
./erc --decrypt -i <input> -o <output> -p <password> [options]
```

Common options:
- `--pow <bits>` : Proof-of-work difficulty in leading zero bits. E.g., `24` means ~2^24 hashing attempts.  
- `--argon-mem <MB>` : Argon2 memory cost in MB. E.g., `128` for 128MB.  
- `--argon-time <t>` : Number of Argon2 iterations.  
- `--timelock <N>` : Number of sequential hash iterations for the time-lock puzzle.

**Example**:

1. **Encrypt**:

   ```bash
   ./erc --encrypt \
     -i secret.txt \
     -o secret.enc \
     -p "MyPassword123" \
     --pow 20 \
     --argon-mem 128 \
     --argon-time 4 \
     --timelock 1000000
   ```

   This sets:
   - PoW difficulty = 20 bits (requires ~1 million SHA-256 hashes on average to find a valid nonce).  
   - Argon2 uses 128 MB and 4 iterations.  
   - Time-lock puzzle of 1,000,000 sequential hashes.  
   - **Legitimate** encryption might take a few seconds to tens of seconds. A brute-force attacker would multiply that cost by each guess.

2. **Decrypt**:

   ```bash
   ./erc --decrypt \
     -i secret.enc \
     -o secret_decrypted.txt \
     -p "MyPassword123"
   ```

   The tool reads the header from `secret.enc` to get all parameters (salt, memory cost, PoW difficulty, time-lock count). Then it solves PoW, performs Argon2, runs time-lock, and finally decrypts.

---

## 5. Security Considerations

1. **Password Strength**:  
   - If your password is extremely weak, the attacker might still guess it in a short list. The energy cost only matters if they do many tries.  

2. **Parameter Tuning**:  
   - **PoW Difficulty**: Each bit doubles the expected number of hashes needed.  
   - **Argon2 Memory**: The bigger the memory requirement, the harder it is for attackers with parallel GPU/ASICs.  
   - **Time-Lock**: Introduces a forced sequential delay. Make sure it’s not so large that legitimate usage is impractical.  

3. **Environmental Impact**:  
   - Deliberately adding CPU/GPU cycles costs energy. For small-scale or critical data, it may be worth it. For mass usage, consider environmental costs.  

4. **Hardware vs. Software**:  
   - Attackers with specialized hardware might do Argon2 or hashing more efficiently. Nonetheless, the cost is still significantly higher than normal “fast” hashing.  

5. **Limits & Future Tech**:  
   - If breakthroughs in **reversible computing** drastically reduce energy per operation, the premise might need re-evaluation.  
   - Still, thermodynamic laws put a **floor** on energy usage for irreversible operations.

---

## 6. Performance Tuning

- **Python**:
  - Adjust parameters in `EncryptionParameters`.  
  - For quick tests, use small PoW difficulty (0-8 bits), minimal Argon2 memory, zero timelock.  
  - For “demo high security,” go bigger (16-24 bits, 64-256MB, million timelock).

- **C++**:
  - Similarly, set `--pow`, `--argon-mem`, `--argon-time`, `--timelock` to your desired levels.  
  - If you have more CPU cores, Argon2 parallelism (`--argon-parallel <p>`) can help speed up *legitimate* key derivation. However, it may also benefit attackers if they have parallel hardware.

- **Batch or Scripting**:  
  - If you’re automating encryption of many files, be mindful that each encryption (and especially decryption) has overhead. Possibly store or reuse partial puzzle solutions if that fits your threat model.

---

## 7. Roadmap & Future Directions

- **Hardware Integration**: Potential for specialized hardware that physically requires a certain energy or time to complete a decryption step.  
- **PUF (Physically Unclonable Function)** synergy: Tie ephemeral secrets to hardware properties.  
- **Hybrid Post-Quantum**: Combine these energy-resistant techniques with a post-quantum algorithm so we have *both* math-based and energy-based security.  
- **Optimized Proof-of-Work**: Currently we do a basic leading-zero-bits approach. Could adapt more advanced or memory-bound PoW.  
- **Distributed Timelock**: Potential methods to do verifiable time-delay encryption (like VRFs or verifiable delay functions).

---

## 8. License & Disclaimer

**License**: The code is provided as-is, under permissive terms (check the repository’s LICENSE file). It depends on external libraries (OpenSSL, Argon2, etc.) which have their own licenses.

**Disclaimer**:  
- **No Warranty**: This is a prototype/research project. Use at your own risk.  
- **Not a Silver Bullet**: Energy-Resistant Cryptography significantly raises brute-force costs, but always combine with standard best practices (strong passwords, multi-factor authentication, secure hardware, etc.).