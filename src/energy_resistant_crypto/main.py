"""
Main module integrating all energy-resistant cryptography components.
Provides high-level encryption and decryption functions that combine
AES encryption with proof-of-work, memory-hard key derivation,
and time-lock puzzles.
"""

from dataclasses import dataclass
from typing import Optional, Tuple, BinaryIO, Callable
import time
import ctypes

from . import aes, pow, kdf, timelock, binary_format

@dataclass
class EncryptionParameters:
    """Parameters controlling the energy cost of decryption."""
    pow_difficulty_bits: int = 0      # Number of leading zero bits for PoW
    argon_mem_cost_kb: int = 16384   # Memory usage in KiB (16 MB default)
    argon_time_cost: int = 3         # Number of Argon2 iterations
    argon_parallelism: int = 1       # Parallelism degree for Argon2
    timelock_iterations: int = 0      # Number of sequential hash iterations

@dataclass
class DecryptionStats:
    """Timing statistics for each phase of decryption."""
    pow_time: float
    kdf_time: float
    timelock_time: float
    aes_time: float
    
    @property
    def total_time(self) -> float:
        """Total time taken for decryption."""
        return self.pow_time + self.kdf_time + self.timelock_time + self.aes_time

def secure_clear(data: bytearray) -> None:
    """Securely clear sensitive data from memory."""
    if data:
        ctypes.memset(data, 0, len(data))

def encrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str,
    params: Optional[EncryptionParameters] = None,
    progress_callback: Optional[Callable[[str, float], None]] = None
) -> None:
    """
    Encrypt data with energy-resistant protection using streaming I/O.
    
    Args:
        in_stream: Input stream containing plaintext
        out_stream: Output stream for encrypted data
        password: Password for encryption
        params: Optional encryption parameters, uses defaults if not provided
        progress_callback: Optional callback(phase: str, progress: float)
    
    Raises:
        ValueError: If parameters are invalid
    """
    if params is None:
        params = EncryptionParameters()
    
    if progress_callback:
        progress_callback("setup", 0.0)
    
    # Generate salt and derive key
    salt = kdf.generate_salt()
    key, _ = kdf.derive_key_argon2(
        password, salt,
        memory_cost_kb=params.argon_mem_cost_kb,
        time_cost=params.argon_time_cost,
        parallelism=params.argon_parallelism,
        progress_callback=lambda p: progress_callback("key_derivation", p * 0.2) if progress_callback else None
    )
    
    try:
        # Generate IV for AES-256
        iv = aes.generate_iv()
        
        # Generate PoW challenge if needed
        challenge = pow.generate_pow_challenge() if params.pow_difficulty_bits > 0 else b''
        
        # Create header
        header = binary_format.FileHeader(
            salt_len=len(salt),
            argon_mem_cost_kb=params.argon_mem_cost_kb,
            argon_time_cost=params.argon_time_cost,
            argon_parallelism=params.argon_parallelism,
            pow_difficulty_bits=params.pow_difficulty_bits,
            challenge_len=len(challenge),
            timelock_iterations=params.timelock_iterations,
            iv=iv
        )
        
        if progress_callback:
            progress_callback("writing_header", 0.3)
        
        # Write header and associated data
        binary_format.write_header(out_stream, header, salt, challenge)
        
        if progress_callback:
            progress_callback("encryption", 0.4)
        
        # Perform time-lock if required
        if params.timelock_iterations > 0:
            _, _ = timelock.compute_hash_chain(
                key,
                params.timelock_iterations,
                progress_callback=lambda c, t: progress_callback(
                    "time_lock",
                    0.4 + (c / t) * 0.3
                ) if progress_callback else None
            )
        
        # Encrypt data
        aes.encrypt_stream(key, iv, in_stream, out_stream)
        
        if progress_callback:
            progress_callback("complete", 1.0)
    
    finally:
        # Clear sensitive data
        if key:
            secure_clear(bytearray(key))

def decrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str,
    progress_callback: Optional[Callable[[str, float], None]] = None
) -> DecryptionStats:
    """
    Decrypt data, performing required computational work.
    
    Args:
        in_stream: Input stream containing encrypted data
        out_stream: Output stream for decrypted data
        password: Password for decryption
        progress_callback: Optional callback(phase: str, progress: float)
    
    Returns:
        DecryptionStats with timing information
    
    Raises:
        ValueError: If decryption fails (wrong password or corrupted data)
    """
    stats = DecryptionStats(0.0, 0.0, 0.0, 0.0)
    key = None
    
    try:
        if progress_callback:
            progress_callback("reading_header", 0.0)
        
        # Read header and associated data
        header, salt, challenge = binary_format.read_header(in_stream)
        
        # 1. Solve proof-of-work puzzle if required
        if header.pow_difficulty_bits > 0:
            if progress_callback:
                progress_callback("proof_of_work", 0.1)
            
            nonce, stats.pow_time = pow.solve_pow(
                challenge,
                header.pow_difficulty_bits
            )
            
            if not pow.check_pow_solution(
                challenge,
                nonce,
                header.pow_difficulty_bits
            ):
                raise ValueError("Proof-of-work verification failed")
        
        # 2. Derive key using Argon2
        if progress_callback:
            progress_callback("key_derivation", 0.25)
        
        key, stats.kdf_time = kdf.derive_key_argon2(
            password,
            salt,
            memory_cost_kb=header.argon_mem_cost_kb,
            time_cost=header.argon_time_cost,
            parallelism=header.argon_parallelism,
            progress_callback=lambda p: progress_callback(
                "key_derivation",
                0.25 + p * 0.25
            ) if progress_callback else None
        )
        
        # 3. Solve time-lock puzzle if required
        if header.timelock_iterations > 0:
            if progress_callback:
                progress_callback("time_lock", 0.5)
            
            _, stats.timelock_time = timelock.compute_hash_chain(
                key,
                header.timelock_iterations,
                progress_callback=lambda c, t: progress_callback(
                    "time_lock",
                    0.5 + (c / t) * 0.25
                ) if progress_callback else None
            )
        
        # 4. Decrypt data
        if progress_callback:
            progress_callback("decryption", 0.75)
        
        start_time = time.perf_counter()
        try:
            aes.decrypt_stream(key, header.iv, in_stream, out_stream)
        except ValueError as e:
            raise ValueError("Decryption failed - incorrect password or corrupted data") from e
        stats.aes_time = time.perf_counter() - start_time
        
        if progress_callback:
            progress_callback("complete", 1.0)
        
        return stats
    
    finally:
        # Clear sensitive data
        if key:
            secure_clear(bytearray(key))

# Legacy API for compatibility with old JSON format
def encrypt(data: bytes,
           password: str,
           params: Optional[EncryptionParameters] = None) -> binary_format.FileHeader:
    """Legacy function for backwards compatibility."""
    from io import BytesIO
    input_stream = BytesIO(data)
    output_stream = BytesIO()
    
    encrypt_stream(input_stream, output_stream, password, params)
    return output_stream.getvalue()

def decrypt(data: bytes,
           password: str,
           progress_callback: Optional[Callable[[str, float], None]] = None) -> Tuple[bytes, DecryptionStats]:
    """Legacy function for backwards compatibility."""
    from io import BytesIO
    input_stream = BytesIO(data)
    output_stream = BytesIO()
    
    stats = decrypt_stream(input_stream, output_stream, password, progress_callback)
    return output_stream.getvalue(), stats