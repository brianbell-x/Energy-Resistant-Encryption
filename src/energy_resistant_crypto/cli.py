"""
Command-line interface for Energy-Resistant Cryptography.
Provides encryption, decryption, and tuning functionality with configurable parameters.
"""

import argparse
import sys
import time
from pathlib import Path

from . import main, kdf, pow as _pow, timelock

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
        description="Energy-Resistant Cryptography (ERC) tool"
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-e", "--encrypt", action="store_true",
                           help="Encrypt mode")
    mode_group.add_argument("-d", "--decrypt", action="store_true",
                           help="Decrypt mode")
    mode_group.add_argument("-t", "--tune", action="store_true",
                           help="Tune hardware parameters and suggest settings")

    parser.add_argument("-i", "--in", dest="input",
                        help="Input file path")
    parser.add_argument("-o", "--out", dest="output",
                        help="Output file path")
    parser.add_argument("-p", "--pass", dest="password",
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
    parser.add_argument("--preset", choices=["low", "medium", "high"],
                        help="Use predefined parameter presets")
    parser.add_argument("--target-time", type=float, default=1.0,
                        help="Target time in seconds for parameter estimation in tune mode")

    return parser.parse_args()

def main_cli() -> int:
    """Main CLI entry point."""
    args = parse_args()

    # Apply presets if specified
    if args.preset:
        presets = {
            "low": {"pow": 0, "argon_mem": 8, "argon_time": 2, "argon_parallel": 1, "timelock": 0},
            "medium": {"pow": 10, "argon_mem": 16, "argon_time": 3, "argon_parallel": 1, "timelock": 100000},
            "high": {"pow": 20, "argon_mem": 32, "argon_time": 5, "argon_parallel": 2, "timelock": 1000000},
        }
        p = presets[args.preset]
        args.pow = p["pow"]
        args.argon_mem = p["argon_mem"]
        args.argon_time = p["argon_time"]
        args.argon_parallel = p["argon_parallel"]
        args.timelock = p["timelock"]

    # Handle tune mode
    if args.tune:
        print(f"Estimating parameters for target time {args.target_time:.2f}s")
        print("Argon2 KDF tuning:")
        mem_kb, time_cost = kdf.estimate_argon2_parameters(
            target_time_seconds=args.target_time
        )
        print(f"  Recommended Argon2 memory cost: {mem_kb//1024} MiB ({mem_kb} KiB)")
        print(f"  Recommended Argon2 time cost: {time_cost} iterations")
        print("Proof-of-Work tuning:")
        pow_bits = _pow.estimate_pow_difficulty(
            target_time_seconds=args.target_time
        )
        print(f"  Recommended PoW difficulty bits: {pow_bits}")
        print("Time-Lock tuning:")
        iters = timelock.estimate_iterations(
            target_time_seconds=args.target_time
        )
        print(f"  Recommended time-lock iterations: {iters}")
        return 0

    # Ensure input and output are provided for encrypt/decrypt
    if not args.input or not args.output:
        print("Error: --in and --out are required for encrypt/decrypt modes", file=sys.stderr)
        return 1

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
                argon_mem_cost_kb=args.argon_mem * 1024,
                argon_time_cost=args.argon_time,
                argon_parallelism=args.argon_parallel,
                timelock_iterations=args.timelock
            )
            # Perform encryption
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                start = time.perf_counter()
                main.encrypt_stream(fin, fout, args.password, params, progress_callback)
                duration = time.perf_counter() - start
            print(f"\nEncryption complete in {format_time(duration)}")
            print(f"Output written to {output_path}")
            if args.pow > 0:
                print(f"Note: A PoW puzzle (difficulty {args.pow} bits) will be required to decrypt this file.")
        else:
            # Decrypt mode
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                start = time.perf_counter()
                stats = main.decrypt_stream(fin, fout, args.password, progress_callback)
                duration = time.perf_counter() - start
            print(f"\nDecryption complete in {format_time(duration)}")
            print(f"Output written to {output_path}")
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