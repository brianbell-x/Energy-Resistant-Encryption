"""
Command-line interface for Energy-Resistant Cryptography.
Provides encryption and decryption functionality with configurable parameters.
"""

import argparse
import sys
from typing import Optional
import time
from pathlib import Path

from . import main

def format_time(seconds: float) -> str:
    """Format time duration in a human-readable way."""
    if seconds < 1:
        return f"{seconds*1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = int(seconds / 60)
        seconds = seconds % 60
        return f"{minutes}m {seconds:.1f}s"

def progress_callback(phase: str, progress: float) -> None:
    """Display progress updates to the user."""
    phases = {
        "setup": "Setting up encryption",
        "key_derivation": "Deriving key with Argon2",
        "writing_header": "Writing file header",
        "encryption": "Encrypting data",
        "time_lock": "Computing time-lock chain",
        "reading_header": "Reading file header",
        "proof_of_work": "Solving proof-of-work puzzle",
        "decryption": "Decrypting data",
        "complete": "Operation complete"
    }
    
    phase_name = phases.get(phase, phase)
    percent = int(progress * 100)
    sys.stderr.write(f"\r{phase_name}... {percent}%")
    sys.stderr.flush()
    
    if progress >= 1.0:
        sys.stderr.write("\n")

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Energy-Resistant Cryptography (ERC) encryption tool"
    )
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-e", "--encrypt", action="store_true",
                           help="Encrypt mode")
    mode_group.add_argument("-d", "--decrypt", action="store_true",
                           help="Decrypt mode")
    
    parser.add_argument("-i", "--in", dest="input", required=True,
                       help="Input file path")
    parser.add_argument("-o", "--out", dest="output", required=True,
                       help="Output file path")
    parser.add_argument("-p", "--pass", dest="password", required=True,
                       help="Passphrase for encryption/decryption")
    
    # Optional parameters for encryption
    parser.add_argument("--pow", type=int, default=0,
                       help="Proof-of-Work difficulty (leading zero bits, default=0)")
    parser.add_argument("--argon-mem", type=int, default=16,
                       help="Argon2 memory cost in MB (default=16)")
    parser.add_argument("--argon-time", type=int, default=3,
                       help="Argon2 iterations (default=3)")
    parser.add_argument("--argon-parallel", type=int, default=1,
                       help="Argon2 parallelism (default=1)")
    parser.add_argument("--timelock", type=int, default=0,
                       help="Hash-chain iterations for time-lock (default=0)")
    
    return parser.parse_args()

def main_cli() -> int:
    """Main CLI entry point."""
    args = parse_args()
    
    try:
        input_path = Path(args.input)
        output_path = Path(args.output)
        
        if not input_path.exists():
            print(f"Error: Input file not found: {input_path}", file=sys.stderr)
            return 1
        
        if output_path.exists():
            print(f"Warning: Output file {output_path} will be overwritten.")
        
        if args.encrypt:
            # Set up encryption parameters
            params = main.EncryptionParameters(
                pow_difficulty_bits=args.pow,
                argon_mem_cost_kb=args.argon_mem * 1024,  # Convert MB to KiB
                argon_time_cost=args.argon_time,
                argon_parallelism=args.argon_parallel,
                timelock_iterations=args.timelock
            )
            
            # Perform encryption
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                start_time = time.perf_counter()
                main.encrypt_stream(fin, fout, args.password, params, progress_callback)
                total_time = time.perf_counter() - start_time
            
            print(f"\nEncryption complete in {format_time(total_time)}")
            print(f"Output written to {output_path}")
            
            if args.pow > 0:
                print(f"Note: A PoW puzzle (difficulty {args.pow} bits) "
                      "will be required to decrypt this file.")
        
        else:  # Decrypt mode
            # Perform decryption
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                start_time = time.perf_counter()
                stats = main.decrypt_stream(fin, fout, args.password, progress_callback)
                total_time = time.perf_counter() - start_time
            
            print(f"\nDecryption complete in {format_time(total_time)}")
            print(f"Output written to {output_path}")
            
            # Print detailed timing statistics
            print("\nTiming breakdown:")
            if stats.pow_time > 0:
                print(f"  Proof-of-Work: {format_time(stats.pow_time)}")
            print(f"  Key Derivation: {format_time(stats.kdf_time)}")
            if stats.timelock_time > 0:
                print(f"  Time-Lock: {format_time(stats.timelock_time)}")
            print(f"  AES Decryption: {format_time(stats.aes_time)}")
        
        return 0
    
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main_cli())