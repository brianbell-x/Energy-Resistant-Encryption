#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <thread>
#include <atomic>
#include <cassert>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Argon2 library header
#include <argon2.h>

using namespace std;

// Structure to hold encryption parameters
struct EncryptionParams {
    uint32_t argon_mem_costKB;    // Memory cost in KiB for Argon2
    uint32_t argon_time_cost;     // Iterations (time cost) for Argon2
    uint32_t argon_parallelism;   // Parallelism degree for Argon2
    uint32_t pow_difficulty_bits; // Number of leading zero bits for PoW
    uint64_t timelock_iterations; // Number of hash iterations for time-lock
};

// Constants for header identification
const uint32_t MAGIC = 0x45524331; // "ERC1" in ASCII

#pragma pack(push, 1)  // use packed struct to avoid padding issues in header layout
struct FileHeader {
    uint32_t magic;
    uint32_t saltLen;
    // (Salt bytes will follow, not directly in struct)
    uint32_t argon_mem_costKB;
    uint32_t argon_time_cost;
    uint32_t argon_parallelism;
    uint32_t pow_difficulty_bits;
    uint32_t challengeLen;
    // (Challenge bytes will follow)
    uint64_t timelock_iterations;
    unsigned char iv[16];  // 16-byte IV for AES-256-CBC
    // (Ciphertext follows after header)
};
#pragma pack(pop)

// Function to check if a SHA-256 hash has the required number of leading zero bits
bool hasLeadingZeroBits(const unsigned char hash[32], uint32_t zeroBits) {
    uint32_t full_bytes = zeroBits / 8;
    uint32_t rem_bits   = zeroBits % 8;
    
    // Check full zero bytes
    for (uint32_t i = 0; i < full_bytes; ++i) {
        if (hash[i] != 0x00) {
            return false;
        }
    }
    if (rem_bits > 0) {
        // Mask for the remaining bits: e.g., if rem_bits = 5, mask = 0xF8 (1111 1000)
        unsigned char mask = 0xFF << (8 - rem_bits);
        if ((hash[full_bytes] & mask) != 0x00) {
            return false;
        }
    }
    return true;
}

// Global atomic flag and nonce for multi-threaded PoW solution
atomic<bool> powSolutionFound(false);
uint64_t powSolutionNonce = 0;  // will hold the found nonce

// Worker function for PoW search (each thread runs this)
void powSearchThread(const vector<unsigned char>& challenge, uint32_t difficulty, uint64_t startNonce, uint64_t step) {
    // Buffer to hold combined challenge + nonce
    vector<unsigned char> data;
    data.reserve(challenge.size() + sizeof(uint64_t));
    // Copy challenge bytes into data buffer
    data.insert(data.end(), challenge.begin(), challenge.end());
    // Append 8 bytes for nonce (will update in loop)
    data.resize(challenge.size() + 8);
    
    // Interpret last 8 bytes of data as the nonce
    uint64_t* noncePtr = reinterpret_cast<uint64_t*>(&data[challenge.size()]);
    *noncePtr = startNonce;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    while (!powSolutionFound.load()) {
        // Compute hash = SHA256(challenge || nonce)
        SHA256(data.data(), data.size(), hash);
        if (hasLeadingZeroBits(hash, difficulty)) {
            // If found a hash with required leading zeros
            powSolutionFound = true;
            powSolutionNonce = *noncePtr;
            return;
        }
        // Increment nonce by step (so each thread explores a distinct sequence)
        *noncePtr += step;
    }
}

// Perform proof-of-work: find a nonce such that SHA256(challenge||nonce) has `difficulty` leading zero bits
uint64_t solveProofOfWork(const vector<unsigned char>& challenge, uint32_t difficulty) {
    if (difficulty == 0) {
        return 0; // No PoW required
    }
    powSolutionFound = false;
    powSolutionNonce = 0;
    unsigned int nThreads = thread::hardware_concurrency();
    if (nThreads == 0) nThreads = 4; // default to 4 if hardware_concurrency is 0
    
    vector<thread> threads;
    threads.reserve(nThreads);
    // Launch threads, each starting at a different nonce, stepping by nThreads
    for (unsigned int i = 0; i < nThreads; ++i) {
        uint64_t start = i;
        uint64_t step  = nThreads;
        threads.emplace_back(powSearchThread, cref(challenge), difficulty, start, step);
    }
    // Join threads (they will all terminate when one finds a solution)
    for (auto& th : threads) {
        th.join();
    }
    return powSolutionNonce;
}

// AES-256-CBC encryption using OpenSSL EVP
bool aes256Encrypt(EVP_CIPHER_CTX* ctx, const unsigned char key[32], const unsigned char iv[16],
                   istream& in, ostream& out) {
    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        cerr << "EVP_EncryptInit_ex failed\n";
        return false;
    }
    
    // Read plaintext from input stream in chunks, encrypt, and write to output stream
    const size_t BUF_SIZE = 4096;
    vector<unsigned char> inBuf(BUF_SIZE);
    vector<unsigned char> outBuf(BUF_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())); 
    
    while (true) {
        in.read(reinterpret_cast<char*>(inBuf.data()), BUF_SIZE);
        streamsize bytesRead = in.gcount();
        if (bytesRead <= 0) break;
        
        int outLen = 0;
        if (1 != EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
            cerr << "EVP_EncryptUpdate failed\n";
            return false;
        }
        out.write(reinterpret_cast<char*>(outBuf.data()), outLen);
    }
    
    // Finalize encryption (flush out padding)
    int finalLen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, outBuf.data(), &finalLen)) {
        cerr << "EVP_EncryptFinal_ex failed (possible padding error)\n";
        return false;
    }
    if (finalLen > 0) {
        out.write(reinterpret_cast<char*>(outBuf.data()), finalLen);
    }
    return true;
}

// AES-256-CBC decryption using OpenSSL EVP
bool aes256Decrypt(EVP_CIPHER_CTX* ctx, const unsigned char key[32], const unsigned char iv[16],
                   istream& in, ostream& out) {
    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        cerr << "EVP_DecryptInit_ex failed\n";
        return false;
    }
    
    const size_t BUF_SIZE = 4096;
    vector<unsigned char> inBuf(BUF_SIZE);
    vector<unsigned char> outBuf(BUF_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    while (true) {
        in.read(reinterpret_cast<char*>(inBuf.data()), BUF_SIZE);
        streamsize bytesRead = in.gcount();
        if (bytesRead <= 0) break;
        
        int outLen = 0;
        if (1 != EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
            cerr << "EVP_DecryptUpdate failed (possibly wrong key or corrupted data)\n";
            return false;
        }
        out.write(reinterpret_cast<char*>(outBuf.data()), outLen);
    }
    
    // Finalize decryption (remove padding)
    int finalLen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, outBuf.data(), &finalLen)) {
        cerr << "EVP_DecryptFinal_ex: decryption failed. Wrong password or data corrupted.\n";
        return false;
    }
    if (finalLen > 0) {
        out.write(reinterpret_cast<char*>(outBuf.data()), finalLen);
    }
    return true;
}

// Utility: secure clear memory (to avoid leaving sensitive data)
void secureClear(vector<unsigned char>& data) {
    if (!data.empty()) {
        memset(data.data(), 0, data.size());
    }
}

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " --encrypt/--decrypt [options]\n"
             << "Options:\n"
             << "  -i, --in <file>       Input file path\n"
             << "  -o, --out <file>      Output file path\n"
             << "  -p, --pass <pass>     Passphrase for encryption/decryption\n"
             << "      --pow <bits>      Proof-of-Work difficulty (leading zero bits, default=0)\n"
             << "      --argon-mem <MB>  Argon2 memory cost in MB (default=16)\n"
             << "      --argon-time <t>  Argon2 iterations (default=3)\n"
             << "      --argon-parallel <p>  Argon2 parallelism (default=1)\n"
             << "      --timelock <N>    Hash-chain iterations for time-lock (default=0)\n";
        return 1;
    }

    bool encryptMode = false, decryptMode = false;
    string inFile, outFile;
    string pass;
    // Set default parameters
    EncryptionParams params;
    params.argon_mem_costKB = 16 * 1024; // 16 MB in KiB
    params.argon_time_cost = 3;
    params.argon_parallelism = 1;
    params.pow_difficulty_bits = 0;
    params.timelock_iterations = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--encrypt" || arg == "-e") {
            encryptMode = true;
        } else if (arg == "--decrypt" || arg == "-d") {
            decryptMode = true;
        } else if ((arg == "--in" || arg == "-i") && i + 1 < argc) {
            inFile = argv[++i];
        } else if ((arg == "--out" || arg == "-o") && i + 1 < argc) {
            outFile = argv[++i];
        } else if ((arg == "--pass" || arg == "-p") && i + 1 < argc) {
            pass = argv[++i];
        } else if (arg == "--pow" && i + 1 < argc) {
            params.pow_difficulty_bits = static_cast<uint32_t>(stoi(argv[++i]));
        } else if (arg == "--argon-mem" && i + 1 < argc) {
            uint32_t memMB = static_cast<uint32_t>(stoi(argv[++i]));
            params.argon_mem_costKB = memMB * 1024; // convert MB to KiB
        } else if (arg == "--argon-time" && i + 1 < argc) {
            params.argon_time_cost = static_cast<uint32_t>(stoi(argv[++i]));
        } else if (arg == "--argon-parallel" && i + 1 < argc) {
            params.argon_parallelism = static_cast<uint32_t>(stoi(argv[++i]));
        } else if (arg == "--timelock" && i + 1 < argc) {
            params.timelock_iterations = static_cast<uint64_t>(stoull(argv[++i]));
        } else {
            cerr << "Unknown or incomplete argument: " << arg << "\n";
            return 1;
        }
    }
    
    if (encryptMode == decryptMode) {
        cerr << "Error: specify exactly one of --encrypt or --decrypt.\n";
        return 1;
    }
    if (inFile.empty() || outFile.empty()) {
        cerr << "Error: input and output files must be specified.\n";
        return 1;
    }
    if (pass.empty()) {
        cerr << "Error: passphrase must be provided via -p or --pass.\n";
        return 1;
    }

    // Open input and output files (binary mode)
    ifstream fin(inFile, ios::binary);
    if (!fin.is_open()) {
        cerr << "Failed to open input file: " << inFile << "\n";
        return 1;
    }
    ofstream fout(outFile, ios::binary);
    if (!fout.is_open()) {
        cerr << "Failed to open output file: " << outFile << "\n";
        return 1;
    }

    if (encryptMode) {
        // --- Encryption process ---
        // 1. Generate random salt for Argon2
        uint32_t saltLen = 16; // use 16-byte salt
        vector<unsigned char> salt(saltLen);
        if (RAND_bytes(salt.data(), saltLen) != 1) {
            cerr << "Random salt generation failed.\n";
            return 1;
        }

        // 2. Derive key using Argon2id
        vector<unsigned char> keyMaterial(32); // 32 bytes = 256-bit key output
        int argonResult = argon2id_hash_raw(params.argon_time_cost, params.argon_mem_costKB,
                                           params.argon_parallelism,
                                           pass.data(), pass.size(),
                                           salt.data(), salt.size(),
                                           keyMaterial.data(), keyMaterial.size());
        if (argonResult != ARGON2_OK) {
            cerr << "Argon2 key derivation failed: " << argon2_error_message(argonResult) << "\n";
            return 1;
        }

        // 3. Time-lock: perform N sequential SHA-256 hashes on keyMaterial
        if (params.timelock_iterations > 0) {
            unsigned char hashBuf[32];
            unsigned char tempBuf[32];
            memcpy(hashBuf, keyMaterial.data(), 32);
            for (uint64_t i = 0; i < params.timelock_iterations; ++i) {
                SHA256(hashBuf, 32, tempBuf);
                memcpy(hashBuf, tempBuf, 32);
            }
            memcpy(keyMaterial.data(), hashBuf, 32);
        }

        // 4. Generate random IV for AES-256-CBC
        unsigned char iv[16];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            cerr << "Random IV generation failed.\n";
            return 1;
        }

        // 5. Generate PoW challenge if needed
        uint32_t challengeLen = 0;
        vector<unsigned char> challenge;
        if (params.pow_difficulty_bits > 0) {
            challengeLen = 16; // use 16-byte challenge
            challenge.resize(challengeLen);
            if (RAND_bytes(challenge.data(), challengeLen) != 1) {
                cerr << "Random challenge generation failed.\n";
                return 1;
            }
        }

        // 6. Write header to output file
        FileHeader header;
        header.magic = MAGIC;
        header.saltLen = saltLen;
        header.argon_mem_costKB = params.argon_mem_costKB;
        header.argon_time_cost = params.argon_time_cost;
        header.argon_parallelism = params.argon_parallelism;
        header.pow_difficulty_bits = params.pow_difficulty_bits;
        header.challengeLen = challengeLen;
        header.timelock_iterations = params.timelock_iterations;
        memcpy(header.iv, iv, 16);

        // Write fixed-size part of header
        fout.write(reinterpret_cast<char*>(&header), sizeof(header));
        // Write variable-length parts: salt and challenge
        fout.write(reinterpret_cast<char*>(salt.data()), saltLen);
        if (challengeLen > 0) {
            fout.write(reinterpret_cast<char*>(challenge.data()), challengeLen);
        }

        // 7. Encrypt the plaintext file data using AES-256-CBC
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Failed to create EVP cipher context\n";
            return 1;
        }
        bool ok = aes256Encrypt(ctx, keyMaterial.data(), iv, fin, fout);
        EVP_CIPHER_CTX_free(ctx);
        if (!ok) {
            cerr << "Encryption failed.\n";
            return 1;
        }

        // 8. Clear sensitive data from memory
        secureClear(keyMaterial);
        secureClear(salt);
        secureClear(challenge);

        cout << "Encryption complete. Output written to " << outFile << "\n";
        if (params.pow_difficulty_bits > 0) {
            cout << "Note: A PoW puzzle (difficulty " << params.pow_difficulty_bits 
                 << " bits) will be required to decrypt this file.\n";
        }
    } else if (decryptMode) {
        // --- Decryption process ---
        // 1. Read and parse header from input file
        FileHeader header;
        fin.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (!fin.good() || header.magic != MAGIC) {
            cerr << "Input file is not a valid ERC encrypted file (magic number mismatch).\n";
            return 1;
        }
        
        uint32_t saltLen = header.saltLen;
        if (saltLen < 8 || saltLen > 1024) { // sanity check salt length
            cerr << "Invalid salt length in header.\n";
            return 1;
        }
        vector<unsigned char> salt(saltLen);
        fin.read(reinterpret_cast<char*>(salt.data()), saltLen);
        if (!fin.good()) {
            cerr << "Error reading salt from file.\n";
            return 1;
        }
        
        uint32_t difficulty = header.pow_difficulty_bits;
        uint32_t challengeLen = header.challengeLen;
        vector<unsigned char> challenge;
        if (challengeLen > 0) {
            if (challengeLen > 1024) {
                cerr << "Invalid challenge length in header.\n";
                return 1;
            }
            challenge.resize(challengeLen);
            fin.read(reinterpret_cast<char*>(challenge.data()), challengeLen);
            if (!fin.good()) {
                cerr << "Error reading PoW challenge from file.\n";
                return 1;
            }
        }
        
        uint64_t timelockN = header.timelock_iterations;
        unsigned char iv[16];
        memcpy(iv, header.iv, 16);

        // 2. Derive the base key with Argon2
        vector<unsigned char> keyMaterial(32);
        int argonResult = argon2id_hash_raw(header.argon_time_cost, header.argon_mem_costKB,
                                           header.argon_parallelism,
                                           pass.data(), pass.size(),
                                           salt.data(), salt.size(),
                                           keyMaterial.data(), keyMaterial.size());
        if (argonResult != ARGON2_OK) {
            cerr << "Argon2 key derivation failed: " << argon2_error_message(argonResult) << "\n";
            return 1;
        }

        // 3. Solve PoW puzzle if required
        if (difficulty > 0) {
            cout << "Solving proof-of-work puzzle (difficulty " << difficulty << " bits)...\n";
            uint64_t nonce = solveProofOfWork(challenge, difficulty);
            
            // Verify solution
            unsigned char hash[32];
            vector<unsigned char> data;
            data.insert(data.end(), challenge.begin(), challenge.end());
            data.resize(challenge.size() + 8);
            *reinterpret_cast<uint64_t*>(&data[challenge.size()]) = nonce;
            SHA256(data.data(), data.size(), hash);
            if (!hasLeadingZeroBits(hash, difficulty)) {
                cerr << "Internal error: PoW solution verification failed.\n";
                return 1;
            }
            cout << "PoW solved. Nonce = " << nonce << "\n";
        }

        // 4. Perform time-lock hash chain
        if (timelockN > 0) {
            cout << "Computing time-lock hash chain (" << timelockN << " iterations)...\n";
            unsigned char hashBuf[32];
            unsigned char tempBuf[32];
            memcpy(hashBuf, keyMaterial.data(), 32);
            for (uint64_t i = 0; i < timelockN; ++i) {
                SHA256(hashBuf, 32, tempBuf);
                memcpy(hashBuf, tempBuf, 32);
            }
            memcpy(keyMaterial.data(), hashBuf, 32);
        }

        // 5. Decrypt ciphertext using the final key
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Failed to create EVP cipher context for decryption\n";
            return 1;
        }
        bool ok = aes256Decrypt(ctx, keyMaterial.data(), iv, fin, fout);
        EVP_CIPHER_CTX_free(ctx);
        
        if (!ok) {
            cerr << "Decryption failed. (Wrong password or file corrupted?)\n";
            ok = false;
        } else {
            cout << "Decryption complete. Output written to " << outFile << "\n";
        }

        // 6. Clear sensitive data
        secureClear(keyMaterial);
        secureClear(salt);
        secureClear(challenge);
        fill(pass.begin(), pass.end(), '\0');

        return ok ? 0 : 1;
    }

    return 0;
}