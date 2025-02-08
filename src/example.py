"""
Example usage of the energy-resistant cryptography implementation.
Demonstrates encryption and decryption with various parameter settings.
"""

import time
from energy_resistant_crypto.main import encrypt, decrypt, EncryptionParameters, EncryptedData

def print_progress(phase: str, progress: float):
    """Simple progress callback to show decryption progress."""
    print(f"{phase}: {progress*100:.1f}%")

def main():
    # Example message to encrypt
    message = b"This is a secret message that requires energy to decrypt!"
    password = "my-secure-password"
    
    print("Energy-Resistant Cryptography Demo")
    print("-" * 40)
    
    # Create encryption parameters
    # These can be adjusted to increase/decrease the energy cost
    params = EncryptionParameters(
        pow_difficulty_bytes=2,      # Requires 2 zero bytes (16 bits) for PoW
        kdf_memory_cost=2**16,      # Use 64 MB of memory for key derivation
        kdf_time_cost=3,            # Perform 3 iterations of Argon2
        timelock_iterations=10**6    # Perform 1 million sequential hashes
    )
    
    print("\nEncryption Parameters:")
    print(f"- PoW Difficulty: {params.pow_difficulty_bytes} zero bytes")
    print(f"- KDF Memory Cost: {params.kdf_memory_cost/1024:.0f} MB")
    print(f"- KDF Time Cost: {params.kdf_time_cost} iterations")
    print(f"- Timelock Iterations: {params.timelock_iterations:,}")
    
    # Encrypt the message
    print("\nEncrypting message...")
    start_time = time.perf_counter()
    encrypted = encrypt(message, password, params)
    encrypt_time = time.perf_counter() - start_time
    print(f"Encryption took {encrypt_time:.2f} seconds")
    
    # Save encrypted data to a file
    print("\nSaving encrypted data...")
    with open("encrypted_message.json", "w") as f:
        f.write(encrypted.to_json())
    
    # Load encrypted data back
    print("\nLoading encrypted data...")
    with open("encrypted_message.json", "r") as f:
        loaded = EncryptedData.from_json(f.read())
    
    # Decrypt with progress updates
    print("\nDecrypting message...")
    print("This will take some time due to enforced computational work...")
    start_time = time.perf_counter()
    decrypted, stats = decrypt(loaded, password, print_progress)
    decrypt_time = time.perf_counter() - start_time
    
    print("\nDecryption Statistics:")
    print(f"- Proof of Work Time: {stats.pow_time:.2f} seconds")
    print(f"- Key Derivation Time: {stats.kdf_time:.2f} seconds")
    print(f"- Timelock Puzzle Time: {stats.timelock_time:.2f} seconds")
    print(f"- AES Decryption Time: {stats.aes_time:.2f} seconds")
    print(f"- Total Time: {stats.total_time:.2f} seconds")
    
    # Verify decryption was successful
    print("\nDecrypted Message:")
    print(decrypted.decode('utf-8'))
    print("\nVerifying decryption...")
    if decrypted == message:
        print("Success! Decrypted message matches original.")
    else:
        print("Error: Decrypted message does not match original!")
    
    # Try with wrong password to demonstrate failure
    print("\nTesting with wrong password...")
    try:
        wrong_decrypted, _ = decrypt(loaded, "wrong-password", print_progress)
        print("Error: Decryption should have failed!")
    except ValueError as e:
        print(f"Correctly failed: {e}")

if __name__ == "__main__":
    main()