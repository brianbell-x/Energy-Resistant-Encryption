from setuptools import setup, find_packages

setup(
    name="energy-resistant-crypto",
    version="1.0.0",
    description="Energy-Resistant Cryptography (ERC) - Making decryption deliberately resource-intensive",
    long_description="""
    Energy-Resistant Cryptography (ERC) is a system that combines strong encryption (AES-256)
    with energy enforcement mechanisms to make decryption deliberately resource-intensive.
    Features include:
    - AES-256 encryption using PyCryptodome
    - Memory-hard key derivation using Argon2id
    - Multi-threaded proof-of-work puzzles
    - Time-lock puzzles using sequential hash chains
    - Configurable security parameters
    - Streaming I/O for large files
    """,
    author="Energy-Resistant Cryptography Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
    install_requires=[
        "pycryptodome>=3.19.1",
        "argon2-cffi>=23.1.0",
    ],
    entry_points={
        'console_scripts': [
            'erc=energy_resistant_crypto.cli:main_cli',
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    keywords="cryptography encryption security proof-of-work argon2 timelock",
)