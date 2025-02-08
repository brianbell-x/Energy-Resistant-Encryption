"""
Binary file format module for Energy-Resistant Cryptography.
Handles reading and writing encrypted data in a compact binary format.
"""

import struct
from dataclasses import dataclass
from typing import BinaryIO, Tuple
import os

# Magic number "ERC1" in ASCII hex
MAGIC = 0x45524331

@dataclass
class FileHeader:
    """Binary file header containing encryption parameters."""
    magic: int = MAGIC
    salt_len: int = 16
    argon_mem_cost_kb: int = 16 * 1024  # 16 MB in KiB
    argon_time_cost: int = 3
    argon_parallelism: int = 1
    pow_difficulty_bits: int = 0
    challenge_len: int = 0
    timelock_iterations: int = 0
    iv: bytes = b'\x00' * 16

    def pack(self) -> bytes:
        """Pack header into bytes for writing to file."""
        return struct.pack(
            '<IIIIIIQQ16s',  # little-endian, 4 uint32s, 1 uint64, 16 bytes
            self.magic,
            self.salt_len,
            self.argon_mem_cost_kb,
            self.argon_time_cost,
            self.argon_parallelism,
            self.pow_difficulty_bits,
            self.challenge_len,
            self.timelock_iterations,
            self.iv
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'FileHeader':
        """Unpack header from bytes read from file."""
        values = struct.unpack('<IIIIIIQQ16s', data)
        return cls(
            magic=values[0],
            salt_len=values[1],
            argon_mem_cost_kb=values[2],
            argon_time_cost=values[3],
            argon_parallelism=values[4],
            pow_difficulty_bits=values[5],
            challenge_len=values[6],
            timelock_iterations=values[7],
            iv=values[8]
        )

    @property
    def size(self) -> int:
        """Get size of packed header in bytes."""
        return struct.calcsize('<IIIIIIQQ16s')

def write_header(f: BinaryIO, header: FileHeader, salt: bytes, challenge: bytes = b'') -> None:
    """
    Write header and associated data to a binary file.
    
    Args:
        f: Binary file object opened for writing
        header: FileHeader instance with parameters
        salt: Salt bytes for key derivation
        challenge: Optional PoW challenge bytes
    
    Raises:
        ValueError: If salt or challenge length doesn't match header
    """
    if len(salt) != header.salt_len:
        raise ValueError(f"Salt length {len(salt)} doesn't match header salt_len {header.salt_len}")
    if len(challenge) != header.challenge_len:
        raise ValueError(f"Challenge length {len(challenge)} doesn't match header challenge_len {header.challenge_len}")
    
    f.write(header.pack())
    f.write(salt)
    if challenge:
        f.write(challenge)

def read_header(f: BinaryIO) -> Tuple[FileHeader, bytes, bytes]:
    """
    Read header and associated data from a binary file.
    
    Args:
        f: Binary file object opened for reading
    
    Returns:
        Tuple of (header, salt, challenge)
    
    Raises:
        ValueError: If magic number doesn't match or lengths are invalid
    """
    # Read fixed-size header first
    header_data = f.read(FileHeader().size)
    if len(header_data) < FileHeader().size:
        raise ValueError("Incomplete header")
    
    header = FileHeader.unpack(header_data)
    if header.magic != MAGIC:
        raise ValueError(f"Invalid magic number: expected {MAGIC:08x}, got {header.magic:08x}")
    
    # Validate lengths
    if header.salt_len < 8 or header.salt_len > 1024:
        raise ValueError(f"Invalid salt length: {header.salt_len}")
    if header.challenge_len > 1024:
        raise ValueError(f"Invalid challenge length: {header.challenge_len}")
    
    # Read variable-length data
    salt = f.read(header.salt_len)
    if len(salt) < header.salt_len:
        raise ValueError("Incomplete salt data")
    
    challenge = b''
    if header.challenge_len > 0:
        challenge = f.read(header.challenge_len)
        if len(challenge) < header.challenge_len:
            raise ValueError("Incomplete challenge data")
    
    return header, salt, challenge

def secure_overwrite(path: str) -> None:
    """
    Securely overwrite a file before deletion.
    
    Args:
        path: Path to file to overwrite
    """
    if not os.path.exists(path):
        return
    
    # Get file size
    size = os.path.getsize(path)
    
    # Overwrite with random data
    with open(path, 'wb') as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    
    # Delete the file
    os.unlink(path)
