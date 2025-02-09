# Energy Resistant Encryption

> In simpler words:  
> This project presents a method of encryption that forces any decryption attempt to use real, significant physical energy. Traditional encryption relies mostly on math problems being hard to solve. If someone someday invents a super fast or quantum computer, normal encryption might be easier to break. With energy resistant encryption, you cannot just be fast; you also need a tremendous amount of actual energy for each wrong guess. This concept uses the laws of physics to keep an attacker from brute forcing keys cheaply, even as technology speeds up.

---

## Introduction and Core Idea

**Overview**  
Energy resistant encryption goes beyond standard math based approaches. It requires attackers to invest real power for each incorrect guess, no matter how efficient or parallel their hardware is. The design philosophy is: if you try billions of keys, you will pay a massive energy bill, potentially beyond anything humans can easily supply.

> In simpler words:  
> The big difference here is that no matter how fast a machine is, it must obey the laws of physics. Every bit flip or guess uses real energy. Brute forcing a large key space becomes impossible without a star sized power source.

---

## Star Scale Energy Requirement

A 256 bit key space has roughly 2^256 possible guesses. Even at room temperature, Landauers Principle tells us that flipping one bit requires a minimum amount of energy. Real computing uses more than this lower limit, but this gives a ballpark figure. Trying 2^256 keys would require energy on the order of many suns worth of mass energy. That is why it is effectively impossible to brute force.

> In simpler words:  
> - **Landauers Principle**: Each bit operation costs a minimum amount of energy tied to temperature.  
> - Brute forcing a 256 bit key requires flipping so many bits that the total energy cost is billions of times more than our suns output.  
> - Even a super advanced quantum computer cannot avoid physical energy limits.

---

## Thermodynamic Foundations

**Entropy, Information, and Energy**  
Cryptographic security depends on randomness (entropy). Landauers Principle states each bit of information processing has an unavoidable physical cost in joules. Bremermanns Limit similarly bounds how many computations a system of given mass energy can perform. By making key derivation and decryption memory heavy or time consuming, we ramp up the total energy required for brute force attempts.

> In simpler words:  
> - **Entropy**: How unpredictable a key is.  
> - **Landauers Principle**: Ties bits to energy usage.  
> - **Bremermanns Limit**: Puts a cap on computations based on available mass energy.  
> - When we intentionally add puzzles or memory heavy steps, the physical energy cost can become astronomical.

---

## How to Enforce Energy Costs 

1. **Memory Hard Functions**:  
   For example, Argon2 requires a big chunk of RAM, creating expensive and parallel resistant operations.  
2. **Proof of Work**:  
   Like solving a puzzle by finding a number (nonce) that produces a hash with certain properties. Each guess is energy spent.  
3. **Time Lock Puzzles**:  
   Sequential hashing cannot be easily done in parallel, forcing a delay no matter the processor speed.  
4. **Physical or Hardware Limits**:  
   Using special devices that measure or limit actual power consumption (like physically unclonable functions) can add further layers.

> In simpler words:  
> These methods force real world resources to be spent, not just processing time. Huge RAM usage, repeated hashing, or forced delays all mean an attacker cannot skip paying the energy cost on every guess.

---

## Practical Applications and Considerations

- **Scalability and Performance**: Legitimate users also pay the energy cost, though at a far smaller scale if they only decrypt occasionally.  
- **Where to Use**: Military, finance, or long term storage where data must remain safe for decades.  
- **Challenges**: Could be slow or costly in daily use, so it is best for data that is rarely decrypted. Also, future hardware might reduce energy per operation but not to zero.  
- **Environmental Impact**: More intense algorithms mean higher electricity usage. Use only where the added protection is worth it.

> In simpler words:  
> - If you read your data often, these methods become inconvenient.  
> - If data is extremely sensitive and rarely accessed, the energy cost overhead might be worth it.  
> - Real devices waste more energy than the theoretical minimum.  
> - Reversible or ultra efficient computing may reduce these costs someday, but will not eliminate them altogether.

---

## Implementation Examples

Below are brief outlines of how you can integrate these energy costs into an encryption workflow. We provide Python and C plus plus code showing a proof of concept. It combines common algorithms like AES 256, Argon2, and sequential hashing to create a resource intensive decryption path.

> In simpler words:  
> We want to show you a working example of how to implement these ideas. The proof of concept uses strong encryption (AES 256) plus special puzzles (proof of work and time lock) and memory hard key derivation (Argon2).

### Directory Layout

    .
    ├── src/energy_resistant_crypto/  (Python modules: aes.py, pow.py, timelock.py, etc)
    ├── production/erc.cpp           (C plus plus single file solution)
    ├── example.py                   (Python usage)
    ├── requirements.txt             (Python dependencies)

> In simpler words:  
> - The Python code is in the `src/energy_resistant_crypto` folder.  
> - The C plus plus version is in `erc.cpp`.  
> - `example.py` shows how to use the Python code.  
> - `requirements.txt` has the libraries you need to install.

---

### Python Usage

**Requirements**: pycryptodome, argon2 cffi

```bash
pip install -r requirements.txt
```

**Quick Demo**:

```bash
python src/example.py
```

This will encrypt a sample message using moderately high settings, produce a file named something like `encrypted_message.json`, then decrypt it.

**Core Functions**:

- `encrypt(data, password, params)`, `decrypt(data, password)`: In memory usage.  
- `encrypt_stream(...)`, `decrypt_stream(...)`: For large file streaming.

> In simpler words:  
> 1. Install the Python libraries.  
> 2. Run `example.py` to try it out.  
> 3. Adjust parameters like proof of work difficulty, Argon2 memory usage, and the number of time lock iterations depending on how much cost you want to impose on each decryption attempt.

---

### C plus plus Usage

**Prerequisites**: openssl, argon2, a C plus plus 17 compiler

**Build**:

```bash
g++ -std=c++17 -O2 -o erc erc.cpp -lssl -lcrypto -largon2 -pthread
```

**Encrypt Example**:

```bash
./erc --encrypt \
    -i secret.txt \
    -o secret.enc \
    -p "MyPassword" \
    --pow 20 \
    --argon-mem 128 \
    --argon-time 4 \
    --timelock 1000000
```

**Decrypt Example**:

```bash
./erc --decrypt \
    -i secret.enc \
    -o decrypted.txt \
    -p "MyPassword"
```

> In simpler words:  
> - This is the C plus plus version.  
> - You set parameters like proof of work bits, Argon2 memory in megabytes, Argon2 time cost, and how many time lock hashes to do.  
> - Then run `--encrypt` or `--decrypt` with the desired inputs.

---

## Security Tuning

1. **Password Strength**: If the password is weak, the attacker only needs a few guesses, so all this energy cost is meaningless.  
2. **Proof of Work**: Each additional proof of work bit doubles the required hashing attempts.  
3. **Argon2 Memory**: High memory cost punishes parallel brute forcing on GPUs.  
4. **Time Lock**: Forces a sequential delay. Combined with proof of work, it makes each wrong guess expensive in both CPU cycles and time.  
5. **Update Over Time**: If future hardware becomes more energy efficient, you can tune the parameters upward.

> In simpler words:  
> - Choose strong passwords.  
> - Increase Argon2 memory if you suspect attackers have powerful parallel machines.  
> - Proof of work and time lock slow down each attempt.  
> - Keep an eye on new hardware capabilities. You might need to increase difficulty over time.

---

## Future Directions

- **Hardware Security Modules**: Could embed minimal energy thresholds that cannot be bypassed.  
- **Proof of Work Variants**: May add dynamic difficulty or memory bounds.  
- **Hybrid Post Quantum**: Combine energy cost methods with math that quantum computers cannot solve easily.  
- **Verifiable Delay Functions (VDF)**: A more advanced kind of time lock puzzle used in distributed systems.

> In simpler words:  
> - You can push this idea further with specialized devices or more complex puzzle algorithms.  
> - Post quantum math plus physical energy requirements would cover both high speed quantum attacks and brute force.  
> - Verifiable Delay Functions are special time lock puzzles that cannot be parallelized and are used for fairness in some block chain systems.

---

## Disclaimer

This is a research prototype. Use it with caution in real world scenarios. No warranty is given.

> In simpler words:  
> This code is for exploration and learning. It might have bugs or limitations. Do not just throw it into production for critical secrets without thorough testing.

---

## Conclusion

Energy resistant encryption merges cryptography with thermodynamic reality. Even if an attacker has near infinite speed, they cannot escape the fact that flipping bits costs joules of energy. By bundling proof of work puzzles, time lock sequences, and memory heavy key derivation into the decryption process, we force a steep energy burden on any brute forcing attempt. This complements both current and post quantum algorithms, raising the bar against future attackers and reminding us that computation always has a physical cost.

> In simpler words:  
> - This method is not just math. It is about the real physical cost of guessing.  
> - If an attacker tries every key, they need enormous energy.  
> - Combining normal crypto with memory hard, proof of work, and time lock elements can seriously deter brute force.  
> - Even quantum speed cannot ignore thermodynamics.