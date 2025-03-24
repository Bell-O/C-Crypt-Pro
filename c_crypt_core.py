#!/usr/bin/env python3
# C-Crypt Core: Shared cryptographic functions for C-Crypt Pro
#
# Original Author: Bell (github.com/Bell-O)
# Core Module Version: 2.0
#
# This module contains all the core cryptographic functions used by
# both the CLI and GUI versions of C-Crypt Pro.

import os
import sys
import base64
import json
import platform
from datetime import datetime
from typing import Tuple, Dict, Any, Optional, Union, List, ByteString

# Try to import optional dependencies
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

# Always required cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: Required 'cryptography' module not found.")
    print("Install with: pip install cryptography")
    print("\nTroubleshooting:")
    print("1. Make sure you're using the correct pip for your Python installation:")
    print(f"   - Try: {sys.executable} -m pip install cryptography argon2-cffi")
    print("2. Check which Python is running this script:")
    print(f"   - Current Python: {sys.executable}")
    sys.exit(1)

# Constants
APP_NAME = "C-Crypt Pro"
APP_VERSION = "2.0"
APP_DIR = os.path.expanduser("~/.c-crypt-pro")
KEY_DIRECTORY = os.path.join(APP_DIR, "keys")
HISTORY_FILE = os.path.join(APP_DIR, "history.json")
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits
DEFAULT_KEY_TYPE = "rsa"

# Ensure app directories exist
os.makedirs(KEY_DIRECTORY, exist_ok=True)


def secure_wipe(data: bytearray) -> None:
    """
    Attempt to securely wipe sensitive data from memory.
    Note: This is best-effort in Python due to garbage collection.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password using Argon2id.
    Falls back to PBKDF2 if argon2-cffi is not available.
    
    Args:
        password: The user's password
        salt: Random salt for key derivation
        
    Returns:
        Derived key suitable for AES-256-GCM
    """
    if HAS_ARGON2:
        # Create a password hasher with secure parameters
        ph = PasswordHasher(
            time_cost=3,        # Number of iterations
            memory_cost=65536,  # 64 MB
            parallelism=4,      # Number of parallel threads
            hash_len=32,        # Output hash length (256 bits)
            salt_len=16,        # Salt length
            type=2              # Argon2id
        )
        
        # Hash the password with the provided salt
        hash_val = ph.hash(password, salt=salt)
        
        # Extract the hash portion (removing the parameters)
        hash_parts = hash_val.split('$')
        raw_hash = hash_parts[-1].encode()
        
        # Use HKDF to derive the final key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            info=b'c-crypt-pro-key',
            backend=default_backend()
        )
        
        return hkdf.derive(raw_hash)
    else:
        # Fallback to PBKDF2 if argon2-cffi is not available
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_000_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())


def generate_keypair(key_type: str = DEFAULT_KEY_TYPE) -> Tuple[bytes, bytes]:
    """
    Generates a new public/private key pair.
    
    Args:
        key_type: Either "rsa" or "curve25519"
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    if key_type.lower() == "rsa":
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Get public key and serialize to PEM format
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    elif key_type.lower() == "curve25519":
        # Generate Ed25519 key pair
        private_key = Ed25519PrivateKey.generate()
        
        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Get public key and serialize to PEM format
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise ValueError("Key type must be either 'rsa' or 'curve25519'")
    
    return private_pem, public_pem


def encrypt_private_key(private_key: bytes, password: str) -> bytes:
    """
    Encrypts a private key with a password.
    
    Args:
        private_key: PEM-encoded private key
        password: Password for encryption
        
    Returns:
        Encrypted private key data
    """
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key from the password
    key = derive_key_argon2(password, salt)
    
    # Encrypt the private key
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)
    
    # Create a metadata dictionary
    metadata = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "method": "password",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    
    # Convert metadata to JSON and encode as Base64
    metadata_json = json.dumps(metadata)
    return base64.b64encode(metadata_json.encode())


def decrypt_private_key(encrypted_key: bytes, password: str) -> bytes:
    """
    Decrypts a private key with a password.
    
    Args:
        encrypted_key: Encrypted private key data
        password: Password for decryption
        
    Returns:
        Decrypted PEM-encoded private key
    """
    try:
        # Decode the Base64 data
        metadata_json = base64.b64decode(encrypted_key).decode()
        
        # Parse the metadata
        metadata = json.loads(metadata_json)
        
        # Extract components
        salt = base64.b64decode(metadata["salt"])
        nonce = base64.b64decode(metadata["nonce"])
        ciphertext = base64.b64decode(metadata["ciphertext"])
        
        # Derive the key from the password
        key = derive_key_argon2(password, salt)
        
        # Decrypt the private key
        aesgcm = AESGCM(key)
        private_key = aesgcm.decrypt(nonce, ciphertext, None)
        
        return private_key
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise ValueError(f"Invalid encrypted key format: {str(e)}")
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted key file")


def save_keypair(private_key: bytes, public_key: bytes, name: str, password: str, description: str = "") -> bool:
    """
    Saves a key pair to disk. The private key is encrypted with a password.
    
    Args:
        private_key: PEM-encoded private key
        public_key: PEM-encoded public key
        name: Name to identify this key pair
        password: Password to encrypt the private key
        description: Optional description of the key pair
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create key directory if it doesn't exist
        os.makedirs(KEY_DIRECTORY, exist_ok=True)
        
        # Encrypt the private key with the password
        encrypted_private_key = encrypt_private_key(private_key, password)
        
        # Create a metadata file for the key pair
        metadata = {
            "name": name,
            "description": description,
            "created": datetime.now().isoformat(),
            "type": "RSA" if b"RSA" in private_key else "Ed25519",
            "has_private": True,
            "has_public": True,
            "private_key_encrypted": True
        }
        
        metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Save encrypted private key
        private_key_path = os.path.join(KEY_DIRECTORY, f"{name}.private.pem")
        with open(private_key_path, 'wb') as f:
            f.write(encrypted_private_key)
        
        # Save public key
        public_key_path = os.path.join(KEY_DIRECTORY, f"{name}.public.pem")
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        
        return True
    except Exception as e:
        print(f"Error saving key pair: {str(e)}")
        return False


def import_key(key_data: bytes, name: str, key_type: str, password: str = None, description: str = "") -> bool:
    """
    Imports an existing key. Private keys will be encrypted.
    
    Args:
        key_data: PEM-encoded key data
        name: Name to identify this key
        key_type: Either "public" or "private"
        password: Password for encrypting private key (required for private keys)
        description: Optional description of the key
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create key directory if it doesn't exist
        os.makedirs(KEY_DIRECTORY, exist_ok=True)
        
        # For private keys, encrypt them
        encrypted_key_data = key_data
        private_key_encrypted = False
        
        if key_type == "private":
            if not password:
                raise ValueError("Password required for importing private keys")
            
            # Encrypt the private key
            encrypted_key_data = encrypt_private_key(key_data, password)
            private_key_encrypted = True
        
        # Check if metadata already exists
        metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
        if os.path.exists(metadata_path):
            # Update existing metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            metadata[f"has_{key_type}"] = True
            if description and not metadata.get("description"):
                metadata["description"] = description
            if key_type == "private":
                metadata["private_key_encrypted"] = private_key_encrypted
        else:
            # Create new metadata
            metadata = {
                "name": name,
                "description": description,
                "created": datetime.now().isoformat(),
                "type": "RSA" if b"RSA" in key_data else "Ed25519",
                "has_private": key_type == "private",
                "has_public": key_type == "public",
                "private_key_encrypted": private_key_encrypted if key_type == "private" else False
            }
        
        # Save metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Save key
        key_path = os.path.join(KEY_DIRECTORY, f"{name}.{key_type}.pem")
        with open(key_path, 'wb') as f:
            f.write(encrypted_key_data)
        
        return True
    except Exception as e:
        print(f"Error importing key: {str(e)}")
        return False


def load_key(name: str, key_type: str = "public", password: str = None) -> bytes:
    """
    Loads a key from disk. If it's a private key and encrypted, uses the provided password.
    
    Args:
        name: Name of the key pair
        key_type: Either "public" or "private"
        password: Password for decrypting private key (if needed)
        
    Returns:
        PEM-encoded key
    """
    key_path = os.path.join(KEY_DIRECTORY, f"{name}.{key_type}.pem")
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # If it's a private key, check if it's encrypted
        if key_type == "private":
            metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if metadata.get("private_key_encrypted", False):
                    if not password:
                        raise ValueError("Password required for encrypted private key")
                    
                    # Decrypt the private key
                    try:
                        return decrypt_private_key(key_data, password)
                    except ValueError as e:
                        raise ValueError(f"Failed to decrypt private key: {str(e)}")
        
        return key_data
    except FileNotFoundError:
        raise FileNotFoundError(f"Key not found: {key_path}")


def list_keys() -> List[Dict[str, Any]]:
    """
    Lists all available keys with metadata.
    
    Returns:
        List of key metadata dictionaries
    """
    if not os.path.exists(KEY_DIRECTORY):
        return []
    
    keys = []
    for filename in os.listdir(KEY_DIRECTORY):
        if filename.endswith(".meta.json"):
            try:
                with open(os.path.join(KEY_DIRECTORY, filename), 'r') as f:
                    metadata = json.load(f)
                    keys.append(metadata)
            except (json.JSONDecodeError, IOError):
                # Skip invalid metadata files
                continue
    
    # Sort keys by creation date (newest first)
    keys.sort(key=lambda k: k.get("created", ""), reverse=True)
    return keys


def delete_key(name: str, key_type: str = "both") -> bool:
    """
    Deletes a key or key pair.
    
    Args:
        name: Name of the key pair
        key_type: "public", "private", or "both"
        
    Returns:
        True if successful, False otherwise
    """
    metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
    private_key_path = os.path.join(KEY_DIRECTORY, f"{name}.private.pem")
    public_key_path = os.path.join(KEY_DIRECTORY, f"{name}.public.pem")
    
    try:
        if key_type in ["private", "both"] and os.path.exists(private_key_path):
            os.remove(private_key_path)
        
        if key_type in ["public", "both"] and os.path.exists(public_key_path):
            os.remove(public_key_path)
        
        if key_type == "both" and os.path.exists(metadata_path):
            os.remove(metadata_path)
        elif os.path.exists(metadata_path):
            # Update metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            if key_type == "private":
                metadata["has_private"] = False
            elif key_type == "public":
                metadata["has_public"] = False
            
            if metadata["has_private"] or metadata["has_public"]:
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
            else:
                os.remove(metadata_path)
        
        return True
    except Exception as e:
        print(f"Error deleting key: {str(e)}")
        return False


def encrypt_symmetric(plaintext: str, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts data using AES-256-GCM.
    
    Args:
        plaintext: Text to encrypt
        key: 32-byte key for AES-256-GCM
        
    Returns:
        Tuple of (nonce, ciphertext, tag)
    """
    # Generate a random nonce
    nonce = os.urandom(12)  # 96 bits is recommended for GCM
    
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt the plaintext
    # In GCM mode, the tag is appended to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    return nonce, ciphertext, b""  # Empty tag as it's included in ciphertext


def decrypt_symmetric(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts data using AES-256-GCM.
    
    Args:
        nonce: Nonce used during encryption
        ciphertext: Encrypted data
        key: 32-byte key for AES-256-GCM
        
    Returns:
        Decrypted plaintext
    """
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt the ciphertext
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode()


def encrypt_asymmetric(data: bytes, public_key_pem: bytes) -> bytes:
    """
    Encrypts data using the recipient's public key.
    
    Args:
        data: Data to encrypt
        public_key_pem: Recipient's PEM-encoded public key
        
    Returns:
        Encrypted data
    """
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    # Check key type and encrypt accordingly
    if isinstance(public_key, rsa.RSAPublicKey):
        # RSA encryption
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    else:
        # For other key types (like Ed25519), we'd need to implement
        # a different approach, possibly using ECIES or similar
        raise NotImplementedError("Only RSA keys are currently supported for asymmetric encryption")


def decrypt_asymmetric(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """
    Decrypts data using the recipient's private key.
    
    Args:
        ciphertext: Encrypted data
        private_key_pem: Recipient's PEM-encoded private key
        
    Returns:
        Decrypted data
    """
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Check key type and decrypt accordingly
    if isinstance(private_key, rsa.RSAPrivateKey):
        # RSA decryption
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    else:
        # For other key types
        raise NotImplementedError("Only RSA keys are currently supported for asymmetric decryption")


def hybrid_encrypt(plaintext: str, recipient_public_key_pem: bytes) -> str:
    """
    Encrypts a message using hybrid encryption (AES + asymmetric).
    
    Args:
        plaintext: Text to encrypt
        recipient_public_key_pem: Recipient's PEM-encoded public key
        
    Returns:
        Base64-encoded encrypted message with metadata
    """
    # Generate a random AES key
    aes_key = os.urandom(AES_KEY_SIZE)
    
    # Encrypt the plaintext with the AES key
    nonce, ciphertext, _ = encrypt_symmetric(plaintext, aes_key)
    
    # Encrypt the AES key with the recipient's public key
    encrypted_key = encrypt_asymmetric(aes_key, recipient_public_key_pem)
    
    # Create a metadata dictionary
    metadata = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    
    # Convert metadata to JSON and encode as Base64
    metadata_json = json.dumps(metadata)
    return base64.b64encode(metadata_json.encode()).decode()


def hybrid_decrypt(encrypted_message: str, private_key_pem: bytes) -> str:
    """
    Decrypts a message using hybrid encryption (AES + asymmetric).
    
    Args:
        encrypted_message: Base64-encoded encrypted message with metadata
        private_key_pem: Recipient's PEM-encoded private key
        
    Returns:
        Decrypted plaintext
    """
    try:
        # Decode the Base64 message
        metadata_json = base64.b64decode(encrypted_message).decode()
        
        # Parse the metadata
        metadata = json.loads(metadata_json)
        
        # Extract components
        encrypted_key = base64.b64decode(metadata["encrypted_key"])
        nonce = base64.b64decode(metadata["nonce"])
        ciphertext = base64.b64decode(metadata["ciphertext"])
        
        # Decrypt the AES key
        aes_key = decrypt_asymmetric(encrypted_key, private_key_pem)
        
        # Decrypt the ciphertext
        plaintext = decrypt_symmetric(nonce, ciphertext, aes_key)
        
        return plaintext
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise ValueError(f"Invalid encrypted message format: {str(e)}")
    except InvalidTag:
        raise ValueError("Decryption failed: Authentication tag verification failed")


def encrypt_with_password(plaintext: str, password: str) -> str:
    """
    Encrypts text using a password (AES-256-GCM with Argon2id).
    
    Args:
        plaintext: Text to encrypt
        password: User's password
        
    Returns:
        Base64-encoded encrypted message with metadata
    """
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key from the password
    key = derive_key_argon2(password, salt)
    
    # Encrypt the plaintext
    nonce, ciphertext, _ = encrypt_symmetric(plaintext, key)
    
    # Create a metadata dictionary
    metadata = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "method": "password",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    
    # Convert metadata to JSON and encode as Base64
    metadata_json = json.dumps(metadata)
    return base64.b64encode(metadata_json.encode()).decode()


def decrypt_with_password(encrypted_message: str, password: str) -> str:
    """
    Decrypts text using a password (AES-256-GCM with Argon2id).
    
    Args:
        encrypted_message: Base64-encoded encrypted message with metadata
        password: User's password
        
    Returns:
        Decrypted plaintext
    """
    try:
        # Decode the Base64 message
        metadata_json = base64.b64decode(encrypted_message).decode()
        
        # Parse the metadata
        metadata = json.loads(metadata_json)
        
        # Check method
        if metadata.get("method") != "password":
            raise ValueError("This message was not encrypted with a password")
        
        # Extract components
        salt = base64.b64decode(metadata["salt"])
        nonce = base64.b64decode(metadata["nonce"])
        ciphertext = base64.b64decode(metadata["ciphertext"])
        
        # Derive the key from the password
        key = derive_key_argon2(password, salt)
        
        # Decrypt the ciphertext
        plaintext = decrypt_symmetric(nonce, ciphertext, key)
        
        return plaintext
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise ValueError(f"Invalid encrypted message format: {str(e)}")
    except InvalidTag:
        raise ValueError("Decryption failed: Authentication tag verification failed")


def decrypt_flightcode_file(encrypted_file_path: str, password: str) -> str:
    """
    Decrypts a file that was encrypted with FlightCode CLI.
    
    Args:
        encrypted_file_path: Path to the encrypted file
        password: Password used to encrypt the file
        
    Returns:
        Decrypted content as a string
    """
    try:
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # FlightCode files start with a signature, check for it
        if not encrypted_data.startswith(b'FCENC'):
            raise ValueError("This file doesn't appear to be encrypted with FlightCode")
        
        # Remove the signature
        encrypted_data = encrypted_data[5:]
        
        # The format is: salt (16 bytes) + nonce (12 bytes) + ciphertext
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        # Derive key from password using the same method as FlightCode
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt the ciphertext
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # FlightCode stores text files as UTF-8
        return plaintext.decode('utf-8')
    except FileNotFoundError:
        raise ValueError(f"File not found: {encrypted_file_path}")
    except InvalidTag:
        raise ValueError("Decryption failed: Incorrect password or corrupted file")
    except Exception as e:
        raise ValueError(f"Failed to decrypt FlightCode file: {str(e)}")


def add_to_history(operation: str, details: Dict[str, Any]) -> None:
    """
    Adds an operation to the history file.
    
    Args:
        operation: Type of operation (e.g., "encrypt", "decrypt")
        details: Details of the operation
    """
    try:
        # Load existing history
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        else:
            history = []
        
        # Add new entry
        entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            **details
        }
        
        # Remove sensitive data
        if "plaintext" in entry:
            entry["plaintext"] = f"[{len(entry['plaintext'])} characters]"
        if "password" in entry:
            entry["password"] = "[redacted]"
        
        history.append(entry)
        
        # Limit history to 100 entries
        if len(history) > 100:
            history = history[-100:]
        
        # Save history
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        # Silently fail if history can't be saved
        pass


def get_history() -> List[Dict[str, Any]]:
    """
    Gets the operation history.
    
    Returns:
        List of history entries
    """
    if not os.path.exists(HISTORY_FILE):
        return []
    
    try:
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
        return history
    except Exception:
        return []

