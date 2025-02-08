"""
AES encryption/decryption module using AES-256 in CBC mode.
Provides streaming encryption functionality with PKCS#7 padding.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import BinaryIO, Tuple
import os

# Default buffer size for streaming operations (4KB like C++ version)
BUFFER_SIZE = 4096

def generate_iv() -> bytes:
    """Generate a random 16-byte IV for AES-CBC."""
    return get_random_bytes(16)

def secure_clear(data: bytearray) -> None:
    """
    Securely clear sensitive data from memory.
    
    Args:
        data: Bytearray to clear
    """
    if data:
        for i in range(len(data)):
            data[i] = 0

class AESCipher:
    """Streaming AES-256-CBC cipher with secure memory handling."""
    
    def __init__(self, key: bytes, iv: bytes, encrypt: bool = True):
        """
        Initialize cipher for encryption or decryption.
        
        Args:
            key: 32-byte key for AES-256
            iv: 16-byte initialization vector
            encrypt: True for encryption, False for decryption
        
        Raises:
            ValueError: If key or IV length is invalid
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        if len(iv) != 16:
            raise ValueError("AES-CBC requires a 16-byte IV")
        
        self.mode = AES.MODE_CBC
        self.buffer = bytearray(BUFFER_SIZE)
        self.cipher = AES.new(key, self.mode, iv)
        self.encrypt_mode = encrypt
        self._finalized = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
    
    def update(self, in_data: bytes) -> bytes:
        """
        Process a chunk of data.
        
        Args:
            in_data: Input bytes to process
        
        Returns:
            Processed bytes (may be empty if not enough data for a block)
        
        Raises:
            RuntimeError: If cipher was already finalized
        """
        if self._finalized:
            raise RuntimeError("Cipher already finalized")
        
        if self.encrypt_mode:
            return self.cipher.encrypt(in_data)
        else:
            return self.cipher.decrypt(in_data)
    
    def finalize(self, final_data: bytes = b'') -> bytes:
        """
        Finalize encryption/decryption and handle padding.
        
        Args:
            final_data: Optional final data to process
        
        Returns:
            Final processed bytes including padding
        
        Raises:
            RuntimeError: If cipher was already finalized
            ValueError: If padding is invalid during decryption
        """
        if self._finalized:
            raise RuntimeError("Cipher already finalized")
        
        self._finalized = True
        result = bytearray()
        
        if final_data:
            if self.encrypt_mode:
                # Add PKCS#7 padding
                pad_len = 16 - (len(final_data) % 16)
                padded = final_data + bytes([pad_len]) * pad_len
                result.extend(self.cipher.encrypt(padded))
            else:
                # Process final full blocks
                result.extend(self.cipher.decrypt(final_data))
                # Remove PKCS#7 padding
                pad_len = result[-1]
                if pad_len < 1 or pad_len > 16:
                    raise ValueError("Invalid padding length")
                if result[-pad_len:] != bytes([pad_len]) * pad_len:
                    raise ValueError("Invalid padding")
                del result[-pad_len:]
        
        return bytes(result)
    
    def cleanup(self) -> None:
        """Securely clear sensitive data."""
        secure_clear(self.buffer)
        self.cipher = None

def encrypt_stream(key: bytes, iv: bytes, in_stream: BinaryIO, out_stream: BinaryIO) -> None:
    """
    Encrypt data from input stream to output stream using AES-256-CBC.
    
    Args:
        key: 32-byte key for AES-256
        iv: 16-byte initialization vector
        in_stream: Input stream to read plaintext from
        out_stream: Output stream to write ciphertext to
    
    Raises:
        ValueError: If key or IV length is invalid
    """
    with AESCipher(key, iv, encrypt=True) as cipher:
        while True:
            data = in_stream.read(BUFFER_SIZE)
            if not data:
                # End of stream - finalize with padding
                final = cipher.finalize()
                if final:
                    out_stream.write(final)
                break
            
            # Process full blocks
            processed = cipher.update(data)
            if processed:
                out_stream.write(processed)

def decrypt_stream(key: bytes, iv: bytes, in_stream: BinaryIO, out_stream: BinaryIO) -> None:
    """
    Decrypt data from input stream to output stream using AES-256-CBC.
    
    Args:
        key: 32-byte key for AES-256
        iv: 16-byte initialization vector
        in_stream: Input stream to read ciphertext from
        out_stream: Output stream to write plaintext to
    
    Raises:
        ValueError: If key or IV length is invalid or padding is corrupt
    """
    with AESCipher(key, iv, encrypt=False) as cipher:
        # Read and process all but the last block to handle padding
        data = bytearray()
        while True:
            chunk = in_stream.read(BUFFER_SIZE)
            if not chunk:
                break
            data.extend(chunk)
        
        if not data:
            raise ValueError("No data to decrypt")
        
        # Process all data with padding
        try:
            result = cipher.update(data[:-16]) + cipher.finalize(data[-16:])
            out_stream.write(result)
        except ValueError as e:
            raise ValueError("Decryption failed - incorrect key or corrupted data") from e

# Legacy API for compatibility
def encrypt_aes_256(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Legacy function for backwards compatibility."""
    iv = generate_iv()
    output = bytearray()
    
    with AESCipher(key, iv, encrypt=True) as cipher:
        output.extend(cipher.update(plaintext))
        output.extend(cipher.finalize())
    
    return iv, bytes(output)

def decrypt_aes_256(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Legacy function for backwards compatibility."""
    output = bytearray()
    
    with AESCipher(key, iv, encrypt=False) as cipher:
        output.extend(cipher.update(ciphertext[:-16]))
        output.extend(cipher.finalize(ciphertext[-16:]))
    
    return bytes(output)