# Energy-Resistant Cryptography (ERC)

This is a C++ implementation of the Energy-Resistant Cryptography (ERC) system. It combines strong encryption (AES-256) with energy enforcement mechanisms to make decryption deliberately resource-intensive.

## Features

- **AES-256 Encryption** using OpenSSL for secure symmetric encryption
- **Energy Enforcement Mechanisms:**
  - **Proof-of-Work (PoW):** Multi-threaded SHA-256 puzzle solving with configurable difficulty
  - **Memory-Hard Key Derivation:** Argon2id for password-based key derivation
  - **Time-Lock Puzzle:** Sequential hash chain computation for enforced time delay
- **Performance Optimizations:** Multi-threading support and efficient streaming I/O
- **CLI Tool Integration:** Command-line interface with configurable parameters
- **Security vs Usability:** Tunable difficulty settings for all mechanisms

## Dependencies

- **OpenSSL** (1.1.1 or above) - For AES-256 encryption and SHA-256 hashing
- **Argon2** library - For memory-hard key derivation
- **C++17 compiler** - For modern language features
- **pthread** - For multi-threading support

### Installing Dependencies

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get install libssl-dev libargon2-dev build-essential
```

#### Linux (Fedora)
```bash
sudo dnf install openssl-devel argon2-devel
```

#### macOS
```bash
brew install openssl argon2
```

#### Windows
Use vcpkg:
```bash
vcpkg install openssl argon2
```
Or manually build OpenSSL and Argon2 from source.

## Building

### Linux/macOS
```bash
# With default library paths
g++ -std=c++17 -O2 -o erc erc.cpp -lssl -lcrypto -largon2 -pthread

# If libraries are in non-standard locations (e.g., macOS with Homebrew)
g++ -std=c++17 -O2 -I/usr/local/include -L/usr/local/lib -o erc erc.cpp -lssl -lcrypto -largon2 -pthread
```

### Windows (MSVC)
```bash
# Using vcpkg
cl /std:c++17 /O2 erc.cpp /I"%VCPKG_ROOT%\installed\x64-windows\include" /link /LIBPATH:"%VCPKG_ROOT%\installed\x64-windows\lib" libssl.lib libcrypto.lib argon2.lib
```

## Usage

### Basic Command Format
```bash
./erc [--encrypt|-e | --decrypt|-d] -i <input> -o <output> -p <passphrase> [options]
```

### Options
- `-i, --in <file>` : Input file path
- `-o, --out <file>` : Output file path
- `-p, --pass <pass>` : Passphrase for encryption/decryption
- `--pow <bits>` : Proof-of-Work difficulty (leading zero bits, default=0)
- `--argon-mem <MB>` : Argon2 memory cost in MB (default=16)
- `--argon-time <t>` : Argon2 iterations (default=3)
- `--argon-parallel <p>` : Argon2 parallelism (default=1)
- `--timelock <N>` : Hash-chain iterations for time-lock (default=0)

### Example Usage

#### Encryption
```bash
# Basic encryption (minimal security parameters)
./erc --encrypt -i secret.txt -o secret.enc -p "MyPassword123"

# High-security encryption
./erc --encrypt -i secret.txt -o secret.enc -p "MyPassword123" \
    --pow 20 \              # Requires ~1M hashes to solve
    --argon-mem 128 \       # Uses 128MB RAM
    --argon-time 4 \        # 4 Argon2 iterations
    --argon-parallel 2 \    # Use 2 threads for Argon2
    --timelock 1000000      # 1M sequential hashes
```

#### Decryption
```bash
# Decryption (parameters are read from the encrypted file)
./erc --decrypt -i secret.enc -o decrypted.txt -p "MyPassword123"
```

## Security Considerations

1. **Password Strength**: While the system adds computational cost to brute-force attempts, you should still use strong passwords. The system cannot compensate for extremely weak passwords.

2. **Parameter Selection**:
   - **PoW Difficulty**: Each bit adds doubles the work required. Start with 16-20 bits for moderate security.
   - **Argon2 Memory**: Higher values (64MB-256MB) make GPU/ASIC attacks more expensive.
   - **Time-lock**: Choose based on acceptable delay (e.g., 1M iterations ≈ few seconds).

3. **Memory Safety**: The implementation securely clears sensitive data from memory after use.

## Performance Tuning

1. **For Quick Testing**: Use minimal parameters
   ```bash
   ./erc -e -i in.txt -o out.enc -p "pass" --pow 0 --argon-mem 8 --argon-time 1
   ```

2. **Balanced Security**: Moderate parameters
   ```bash
   ./erc -e -i in.txt -o out.enc -p "pass" --pow 18 --argon-mem 32 --argon-time 3
   ```

3. **High Security**: Strong parameters (expect longer processing time)
   ```bash
   ./erc -e -i in.txt -o out.enc -p "pass" --pow 24 --argon-mem 256 --argon-time 4 --timelock 5000000
   ```

## Troubleshooting

1. **Compilation Errors**:
   - Ensure all dependencies are installed
   - Check library paths match your system
   - For Windows, ensure VCPKG_ROOT is set correctly

2. **Runtime Errors**:
   - "EVP_DecryptFinal_ex failed": Usually indicates wrong password
   - Memory allocation failures: Reduce Argon2 memory parameter
   - "Random generation failed": Check OpenSSL installation

3. **Performance Issues**:
   - Long decryption times: Reduce difficulty parameters
   - High memory usage: Lower the Argon2 memory parameter
   - CPU maxed out: Reduce PoW difficulty or time-lock iterations

## License

This implementation is provided as-is. Use at your own risk. The code relies on OpenSSL and Argon2, which have their own licenses that must be respected.