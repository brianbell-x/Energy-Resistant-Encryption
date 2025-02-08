"""
Key Derivation Function module using Argon2.
Implements memory-hard key derivation to make password cracking computationally expensive.
"""

from argon2 import low_level
import os
from typing import Tuple, Optional, Callable
import time
import ctypes

def secure_clear(data: bytearray) -> None:
    """
    Securely clear sensitive data from memory.
    
    Args:
        data: Bytearray to clear
    """
    if data:
        ctypes.memset(data, 0, len(data))

def generate_salt() -> bytes:
    """
    Generate a random salt for key derivation.
    
    Returns:
        16 random bytes to use as salt
    """
    return os.urandom(16)

def validate_argon2_params(memory_cost_kb: int, time_cost: int, parallelism: int) -> None:
    """
    Validate Argon2 parameters.
    
    Args:
        memory_cost_kb: Memory usage in kibibytes (KiB)
        time_cost: Number of iterations
        parallelism: Degree of parallelism (threads)
    
    Raises:
        ValueError: If parameters are invalid
    """
    if memory_cost_kb < 8 * parallelism:
        raise ValueError("memory_cost_kb must be at least 8 * parallelism")
    if memory_cost_kb > 2**32:
        raise ValueError("memory_cost_kb too large (max 4TB)")
    if time_cost < 1:
        raise ValueError("time_cost must be at least 1")
    if time_cost > 2**32:
        raise ValueError("time_cost too large")
    if parallelism < 1:
        raise ValueError("parallelism must be at least 1")
    if parallelism > 2**24:
        raise ValueError("parallelism too large")

def derive_key_argon2(
    password: str, 
    salt: bytes, 
    key_length: int = 32,
    memory_cost_kb: int = 16 * 1024,  # 16 MB in KiB
    time_cost: int = 3,               # iterations
    parallelism: int = 1,
    progress_callback: Optional[Callable[[float], None]] = None
) -> Tuple[bytes, float]:
    """
    Derive a key from a password using Argon2id (memory-hard KDF).
    
    Args:
        password: The password to derive key from
        salt: Salt bytes for the derivation
        key_length: Length of the derived key in bytes
        memory_cost_kb: Memory usage in kibibytes (KiB)
        time_cost: Number of iterations
        parallelism: Degree of parallelism (threads)
        progress_callback: Optional callback(progress: float) for updates
    
    Returns:
        Tuple of (derived_key, time_taken_seconds)
    
    Raises:
        ValueError: If parameters are invalid
    """
    if not 16 <= key_length <= 64:
        raise ValueError("key_length must be between 16 and 64 bytes")
    if len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    
    validate_argon2_params(memory_cost_kb, time_cost, parallelism)
    
    # Convert password to bytes and clear original from memory if possible
    password_bytes = bytearray(password.encode('utf-8'))
    try:
        # Try to clear original password string from memory
        ctypes.memset(id(password) + 20, 0, len(password))
    except:
        pass  # Best effort, may not work on all Python implementations
    
    start_time = time.perf_counter()
    
    try:
        # Use Argon2id variant which provides the best security against both
        # side-channel and GPU-based attacks
        key = low_level.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost_kb,
            parallelism=parallelism,
            hash_len=key_length,
            type=low_level.Type.ID
        )
        
        if progress_callback:
            progress_callback(1.0)  # Argon2 doesn't provide progress updates
        
        end_time = time.perf_counter()
        return key, end_time - start_time
    
    finally:
        # Clear sensitive data
        secure_clear(password_bytes)

def estimate_argon2_parameters(
    target_time_seconds: float = 1.0,
    max_memory_mb: int = 1024  # 1 GB max
) -> Tuple[int, int]:
    """
    Estimate Argon2 parameters (memory_cost, time_cost) to achieve a target
    derivation time on the current hardware.
    
    Args:
        target_time_seconds: Desired time for key derivation
        max_memory_mb: Maximum memory to use in MB
    
    Returns:
        Tuple of (memory_cost_kb, time_cost)
        - memory_cost_kb in KiB (power of 2)
        - time_cost (iterations)
    """
    # Start with baseline parameters
    memory_cost_kb = min(16 * 1024, max_memory_mb * 1024)  # Start with 16 MB or max
    time_cost = 1
    parallelism = 1
    test_password = "test"
    salt = generate_salt()
    
    # Measure baseline performance
    _, baseline_time = derive_key_argon2(
        test_password,
        salt,
        memory_cost_kb=memory_cost_kb,
        time_cost=time_cost,
        parallelism=parallelism
    )
    
    # Adjust time_cost to get close to target time
    # We prefer adjusting time_cost over memory_cost as it's more predictable
    time_cost = max(1, int(target_time_seconds / baseline_time))
    
    # If time_cost would be too high, increase memory instead
    if time_cost > 10:
        # Increase memory in powers of 2 until we're close to target time
        # or hit memory limit
        while (time_cost > 10 and 
               memory_cost_kb < max_memory_mb * 1024 and 
               memory_cost_kb < 2**20):  # Cap at 1 GB
            memory_cost_kb *= 2
            time_cost = max(1, int(target_time_seconds / baseline_time))
    
    return memory_cost_kb, time_cost

class Argon2Context:
    """Context manager for Argon2 key derivation with secure cleanup."""
    
    def __init__(self, 
                 password: str,
                 salt: bytes,
                 key_length: int = 32,
                 memory_cost_kb: int = 16 * 1024,
                 time_cost: int = 3,
                 parallelism: int = 1):
        self.password = password
        self.salt = salt
        self.key_length = key_length
        self.memory_cost_kb = memory_cost_kb
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.key = None
        self.password_bytes = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.password_bytes:
            secure_clear(self.password_bytes)
        if self.key:
            secure_clear(bytearray(self.key))
    
    def derive(self) -> bytes:
        """Derive key with secure cleanup."""
        self.key, _ = derive_key_argon2(
            self.password,
            self.salt,
            self.key_length,
            self.memory_cost_kb,
            self.time_cost,
            self.parallelism
        )
        return self.key