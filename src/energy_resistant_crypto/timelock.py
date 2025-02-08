"""
Time-Lock Puzzle module implementing sequential computation delays.
Forces a minimum time delay through sequential hash chain computations.
"""

import hashlib
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

def generate_timelock_seed() -> bytes:
    """
    Generate a random seed for the time-lock puzzle.
    
    Returns:
        32 random bytes to use as the puzzle seed
    """
    return os.urandom(32)

def compute_hash_chain(
    seed: bytes,
    iterations: int,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    chunk_size: int = 10000
) -> Tuple[bytes, float]:
    """
    Compute a chain of SHA-256 hashes sequentially.
    This operation cannot be parallelized as each hash depends on the previous result.
    Uses double buffering to avoid in-place hashing issues.
    
    Args:
        seed: Initial value for the hash chain
        iterations: Number of hash iterations to perform
        progress_callback: Optional callback(current, total) for progress updates
        chunk_size: Number of iterations per progress update
    
    Returns:
        Tuple of (final_hash, time_taken_seconds)
    
    Raises:
        ValueError: If iterations is negative
    """
    if iterations < 0:
        raise ValueError("iterations must be non-negative")
    
    if iterations == 0:
        return seed, 0.0
    
    start_time = time.perf_counter()
    
    # Use double buffering like C++ implementation
    hash_buf = bytearray(32)  # primary buffer
    temp_buf = bytearray(32)  # temporary buffer for hash output
    
    # Initialize hash_buf with seed
    hash_buf[:] = seed
    
    # Process in chunks for progress reporting
    remaining = iterations
    completed = 0
    
    while remaining > 0:
        current_chunk = min(chunk_size, remaining)
        
        for _ in range(current_chunk):
            # Compute SHA-256(hash_buf) into temp_buf
            temp_buf[:] = hashlib.sha256(hash_buf).digest()
            # Swap buffers for next iteration
            hash_buf, temp_buf = temp_buf, hash_buf
        
        remaining -= current_chunk
        completed += current_chunk
        
        if progress_callback:
            progress_callback(completed, iterations)
    
    end_time = time.perf_counter()
    
    # Get final result
    result = bytes(hash_buf)
    
    # Clear sensitive data
    secure_clear(hash_buf)
    secure_clear(temp_buf)
    
    return result, end_time - start_time

def verify_hash_chain(seed: bytes, final_hash: bytes, iterations: int) -> bool:
    """
    Verify that a given final_hash is the result of the hash chain computation.
    Useful for proving the time-lock puzzle was actually solved.
    
    Args:
        seed: Initial value used
        final_hash: Claimed result of the hash chain
        iterations: Number of iterations that should have been performed
    
    Returns:
        True if final_hash is correct, False otherwise
    """
    result, _ = compute_hash_chain(seed, iterations)
    return result == final_hash

def estimate_iterations(target_time_seconds: float = 1.0,
                      sample_size: int = 10000) -> int:
    """
    Estimate the number of hash chain iterations needed to achieve
    a target computation time on the current hardware.
    
    Args:
        target_time_seconds: Desired time for puzzle computation
        sample_size: Number of iterations to test for timing
    
    Returns:
        Recommended number of iterations
    """
    # Time how many iterations we can do per second
    seed = generate_timelock_seed()
    _, sample_time = compute_hash_chain(seed, sample_size)
    
    # Calculate iterations needed for target time
    iterations_per_second = sample_size / sample_time
    needed_iterations = int(iterations_per_second * target_time_seconds)
    
    # Round to nearest million for cleaner numbers
    return max(1_000_000, round(needed_iterations / 1_000_000) * 1_000_000)

class TimeLockPuzzle:
    """Class for creating and solving time-lock puzzles with progress tracking."""
    
    def __init__(self, iterations: int):
        """
        Initialize a new time-lock puzzle.
        
        Args:
            iterations: Number of hash chain iterations required
        """
        self.iterations = iterations
        self.seed = generate_timelock_seed()
        self._solution = None
        self._solve_time = None
    
    @property
    def solution(self) -> Optional[bytes]:
        """Get the solution if puzzle has been solved."""
        return self._solution
    
    @property
    def solve_time(self) -> Optional[float]:
        """Get the time taken to solve if puzzle has been solved."""
        return self._solve_time
    
    def solve(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> bytes:
        """
        Solve the puzzle by computing the hash chain.
        
        Args:
            progress_callback: Optional callback(current, total) for progress updates
        
        Returns:
            Final hash value (solution)
        """
        self._solution, self._solve_time = compute_hash_chain(
            self.seed,
            self.iterations,
            progress_callback
        )
        return self._solution
    
    def verify(self, claimed_solution: bytes) -> bool:
        """
        Verify a claimed solution to the puzzle.
        
        Args:
            claimed_solution: The solution to verify
        
        Returns:
            True if solution is correct
        """
        return verify_hash_chain(self.seed, claimed_solution, self.iterations)