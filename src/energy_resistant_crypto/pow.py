"""
Proof-of-Work module implementing computational puzzles.
Requires finding a nonce such that SHA-256(challenge || nonce) has N leading zero bits.
"""

import hashlib
import os
from typing import Tuple
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

def generate_pow_challenge() -> bytes:
    """
    Generate a random challenge for proof-of-work.
    
    Returns:
        16 random bytes to use as the challenge
    """
    return os.urandom(16)

def has_leading_zero_bits(hash_val: bytes, zero_bits: int) -> bool:
    """
    Check if a hash has the required number of leading zero bits.
    
    Args:
        hash_val: The hash value to check
        zero_bits: Number of leading zero bits required
    
    Returns:
        True if hash has required leading zeros
    """
    full_bytes = zero_bits // 8
    rem_bits = zero_bits % 8
    
    # Check full zero bytes
    for i in range(full_bytes):
        if hash_val[i] != 0:
            return False
    
    # Check remaining bits using mask
    if rem_bits > 0:
        mask = 0xFF << (8 - rem_bits)
        if (hash_val[full_bytes] & mask) != 0:
            return False
    
    return True

def check_pow_solution(challenge: bytes, nonce: int, difficulty_bits: int) -> bool:
    """
    Verify if a nonce is a valid solution to the proof-of-work puzzle.
    
    Args:
        challenge: The challenge bytes
        nonce: The proposed solution nonce
        difficulty_bits: Number of leading zero bits required
    
    Returns:
        True if nonce produces a valid solution, False otherwise
    """
    nonce_bytes = nonce.to_bytes(8, 'little', signed=False)
    hash_val = hashlib.sha256(challenge + nonce_bytes).digest()
    return has_leading_zero_bits(hash_val, difficulty_bits)

class PowSolver:
    """Thread-safe proof-of-work solver using multiple threads."""
    
    def __init__(self, challenge: bytes, difficulty_bits: int):
        self.challenge = challenge
        self.difficulty_bits = difficulty_bits
        self.solution_found = threading.Event()
        self.solution_nonce = None
        self.start_time = None
        self.end_time = None
    
    def _search_worker(self, start_nonce: int, step: int) -> None:
        """Worker function for each thread to search a range of nonces."""
        nonce = start_nonce
        while not self.solution_found.is_set():
            if check_pow_solution(self.challenge, nonce, self.difficulty_bits):
                self.solution_nonce = nonce
                self.end_time = time.perf_counter()
                self.solution_found.set()
                break
            nonce += step
    
    def solve(self, max_attempts: int = 2**32) -> Tuple[int, float]:
        """
        Find a nonce that solves the proof-of-work puzzle using multiple threads.
        
        Args:
            max_attempts: Maximum number of attempts before giving up
        
        Returns:
            Tuple of (nonce, time_taken_seconds)
        
        Raises:
            ValueError: If difficulty_bits is not between 1 and 32
            RuntimeError: If no solution found within max_attempts
        """
        if not 1 <= self.difficulty_bits <= 32:
            raise ValueError("difficulty_bits must be between 1 and 32")
        
        if self.difficulty_bits == 0:
            return 0, 0.0
        
        # Use number of CPU cores for threading
        num_threads = multiprocessing.cpu_count()
        if num_threads == 0:
            num_threads = 4  # fallback if cpu_count fails
        
        self.start_time = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Each thread starts at a different nonce and increments by num_threads
            futures = [
                executor.submit(self._search_worker, i, num_threads)
                for i in range(num_threads)
            ]
            
            # Wait for solution or all threads to finish
            self.solution_found.wait()
            
            # Cancel any remaining threads
            for future in futures:
                future.cancel()
        
        if self.solution_nonce is None:
            raise RuntimeError(f"No solution found within {max_attempts} attempts")
        
        return self.solution_nonce, self.end_time - self.start_time

def solve_pow(challenge: bytes, difficulty_bits: int, max_attempts: int = 2**32) -> Tuple[int, float]:
    """
    Find a nonce that solves the proof-of-work puzzle.
    
    Args:
        challenge: The challenge bytes
        difficulty_bits: Number of leading zero bits required in hash
        max_attempts: Maximum number of attempts before giving up
    
    Returns:
        Tuple of (nonce, time_taken_seconds)
        The nonce will produce a hash with difficulty_bits leading zeros when
        combined with the challenge.
    
    Raises:
        ValueError: If difficulty_bits is not between 1 and 32
        RuntimeError: If no solution found within max_attempts
    """
    solver = PowSolver(challenge, difficulty_bits)
    return solver.solve(max_attempts)

def estimate_pow_difficulty(target_time_seconds: float = 1.0, 
                          sample_size: int = 1000) -> int:
    """
    Estimate the proof-of-work difficulty (in bits) needed to achieve
    a target solution time on the current hardware.
    
    Args:
        target_time_seconds: Desired time to solve puzzle
        sample_size: Number of hashes to test for timing
    
    Returns:
        Recommended difficulty in bits (1-32)
    """
    # Time how many hashes we can do per second
    challenge = generate_pow_challenge()
    start = time.perf_counter()
    for i in range(sample_size):
        nonce_bytes = i.to_bytes(8, 'little', signed=False)
        _ = hashlib.sha256(challenge + nonce_bytes).digest()
    end = time.perf_counter()
    
    hashes_per_second = sample_size / (end - start)
    
    # Each difficulty bit doubles the work required
    # So we can estimate the difficulty needed for the target time
    total_hashes_needed = hashes_per_second * target_time_seconds
    difficulty_bits = min(32, max(1, int(total_hashes_needed.bit_length())))
    
    return difficulty_bits