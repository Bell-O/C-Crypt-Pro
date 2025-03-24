#!/usr/bin/env python3
# C-Crypt Pro CLI with Color
# Advanced Encryption Tool with Command Line Interface

import os
import sys
import base64
import json
import platform
import shutil
import time
import getpass
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import traceback

# Try to import colorama for cross-platform color support
try:
    from colorama import init, Fore, Back, Style
    init()  # Initialize colorama
    has_color = True
except ImportError:
    # Create dummy color classes if colorama is not available
    class DummyColor:
        def __getattr__(self, name):
            return ""
    
    Fore = DummyColor()
    Back = DummyColor()
    Style = DummyColor()
    has_color = False
    print("Note: Install 'colorama' for colored output: pip install colorama")

# Import cryptography libraries
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
    print(f"{Fore.RED}Error: Required 'cryptography' module not found.{Style.RESET_ALL}")
    print(f"Install with: {Fore.YELLOW}pip install cryptography{Style.RESET_ALL}")
    sys.exit(1)

# Try to import Argon2 (optional)
try:
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import VerifyMismatchError
    has_argon2 = True
except ImportError:
    has_argon2 = False

# Constants
APP_NAME = "C-Crypt Pro"
APP_VERSION = "2.0.0"
APP_DIR = os.path.expanduser("~/.c-crypt-pro")
KEY_DIRECTORY = os.path.join(APP_DIR, "keys")
HISTORY_FILE = os.path.join(APP_DIR, "history.json")
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits
DEFAULT_KEY_TYPE = "rsa"

# Color constants
COLOR_TITLE = Fore.CYAN
COLOR_MENU = Fore.GREEN
COLOR_PROMPT = Fore.YELLOW
COLOR_SUCCESS = Fore.GREEN
COLOR_ERROR = Fore.RED
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.BLUE
COLOR_HIGHLIGHT = Fore.MAGENTA
COLOR_RESET = Style.RESET_ALL

# Ensure app directories exist
os.makedirs(KEY_DIRECTORY, exist_ok=True)

# Cryptography functions
def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password using Argon2id.
    Falls back to PBKDF2 if argon2-cffi is not available.
    """
    if has_argon2:
        # Create a password hasher with secure parameters
        ph = PasswordHasher(
            time_cost=3,        # Number of iterations
            memory_cost=65536,  # 64 MB
            parallelism=4,      # Number of parallel threads
            hash_len=32,        # Output hash length (256 bits)
            salt_len=16,        # Salt length
            type=Type.ID        # Argon2id (use Type.ID instead of integer 2)
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
    """Generates a new public/private key pair."""
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
    """Encrypts a private key with a password."""
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
    """Decrypts a private key with a password."""
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
    """Saves a key pair to disk. The private key is encrypted with a password."""
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
        print(f"{COLOR_ERROR}Error saving key pair: {str(e)}{COLOR_RESET}")
        return False

def list_keys() -> List[Dict[str, Any]]:
    """Lists all available keys with metadata."""
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

def load_key(name: str, key_type: str = "public", password: str = None) -> bytes:
    """Loads a key from disk. If it's a private key and encrypted, uses the provided password."""
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

def encrypt_symmetric(plaintext: str, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypts data using AES-256-GCM."""
    # Generate a random nonce
    nonce = os.urandom(12)  # 96 bits is recommended for GCM
    
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt the plaintext
    # In GCM mode, the tag is appended to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    return nonce, ciphertext, b""  # Empty tag as it's included in ciphertext

def decrypt_symmetric(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """Decrypts data using AES-256-GCM."""
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt the ciphertext
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode()

def encrypt_asymmetric(data: bytes, public_key_pem: bytes) -> bytes:
    """Encrypts data using the recipient's public key."""
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
    """Decrypts data using the recipient's private key."""
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
    """Encrypts a message using hybrid encryption (AES + asymmetric)."""
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
    """Decrypts a message using hybrid encryption (AES + asymmetric)."""
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
    """Encrypts text using a password (AES-256-GCM with Argon2id)."""
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
    """Decrypts text using a password (AES-256-GCM with Argon2id)."""
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

def add_to_history(operation: str, details: Dict[str, Any]) -> None:
    """Adds an operation to the history file."""
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
    """Gets the operation history."""
    if not os.path.exists(HISTORY_FILE):
        return []
    
    try:
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
        return history
    except Exception:
        return []

# CLI Functions
def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_banner():
    """Prints the application banner."""
    clear_screen()
    print(f"""{COLOR_TITLE}
_____       _____                  _     _____           
 / ____|     / ____|                | |   |  __ \          
| |   ______| |     _ __ _   _ _ __ | |_  | |__) | __ ___  
| |  |______| |    | '__| | | | '_ \| __| |  ___/ '__/ _ \ 
| |____     | |____| |  | |_| | |_) | |_  | |   | | | (_) |
 \_____|     \_____|_|   \__, | .__/ \__| |_|   |_|  \___/ 
                          __/ | |                          
                         |___/|_|                          
{COLOR_RESET}
{COLOR_INFO}Version {APP_VERSION} - Advanced Encryption Tool
Original by Bell (github.com/Bell-O)
Pro Version with enhanced usability and security
---------------------------------------------------{COLOR_RESET}
""")

def print_main_menu():
    """Prints the main menu options."""
    print(f"\n{COLOR_MENU}Main Menu:{COLOR_RESET}\n")
    print(f"{COLOR_HIGHLIGHT}Encryption & Decryption:{COLOR_RESET}")
    print(f"{COLOR_MENU}1. Quick Encrypt (Password){COLOR_RESET}")
    print(f"{COLOR_MENU}2. Quick Decrypt (Password){COLOR_RESET}")
    print(f"{COLOR_MENU}3. Encrypt with Public Key{COLOR_RESET}")
    print(f"{COLOR_MENU}4. Decrypt with Private Key{COLOR_RESET}")
    print("")
    print(f"{COLOR_HIGHLIGHT}Key Management:{COLOR_RESET}")
    print(f"{COLOR_MENU}5. Generate New Key Pair{COLOR_RESET}")
    print(f"{COLOR_MENU}6. View My Keys{COLOR_RESET}")
    print(f"{COLOR_MENU}7. Import Key{COLOR_RESET}")
    print(f"{COLOR_MENU}8. Export Key{COLOR_RESET}")
    print(f"{COLOR_MENU}9. Delete Key{COLOR_RESET}")
    print("")
    print(f"{COLOR_HIGHLIGHT}Utilities:{COLOR_RESET}")
    print(f"{COLOR_MENU}10. View Recent Activity{COLOR_RESET}")
    print(f"{COLOR_MENU}11. Check System Requirements{COLOR_RESET}")
    print(f"{COLOR_MENU}12. Help & Documentation{COLOR_RESET}")
    print("")
    print(f"{COLOR_HIGHLIGHT}External Compatibility:{COLOR_RESET}")
    print(f"{COLOR_MENU}13. Decrypt FlightCode File{COLOR_RESET}")
    print(f"{COLOR_MENU}0. Exit{COLOR_RESET}")
    print("")

def wait_for_key():
    """Waits for the user to press Enter."""
    input(f"\n{COLOR_PROMPT}Press Enter to continue...{COLOR_RESET}")

def quick_encrypt():
    """Encrypts text with a password."""
    print_banner()
    print(f"{COLOR_TITLE}Quick Encrypt (Password){COLOR_RESET}\n")
    print("This will encrypt your text with a password.")
    print("Anyone with the password will be able to decrypt it.\n")
    
    # Get plaintext
    plaintext = input(f"{COLOR_PROMPT}Enter the text to encrypt: {COLOR_RESET}")
    if not plaintext:
        print(f"{COLOR_ERROR}Error: No text entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get password
    password = getpass.getpass(f"{COLOR_PROMPT}Enter a strong password: {COLOR_RESET}")
    if not password:
        print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    confirm_password = getpass.getpass(f"{COLOR_PROMPT}Confirm password: {COLOR_RESET}")
    if password != confirm_password:
        print(f"{COLOR_ERROR}Error: Passwords do not match.{COLOR_RESET}")
        wait_for_key()
        return
    
    try:
        print(f"\n{COLOR_INFO}Encrypting...{COLOR_RESET}")
        encrypted = encrypt_with_password(plaintext, password)
        
        print(f"\n{COLOR_SUCCESS}Encryption successful!{COLOR_RESET}")
        print(f"\n{COLOR_HIGHLIGHT}Encrypted text:{COLOR_RESET}")
        print(encrypted)
        
        # Add to history
        add_to_history("encrypt", {
            "method": "password",
            "plaintext": plaintext
        })
        
        # Ask if user wants to save to file
        save_to_file = input(f"\n{COLOR_PROMPT}Save to file? (y/n): {COLOR_RESET}").lower()
        if save_to_file == 'y':
            file_path = input(f"{COLOR_PROMPT}Enter file path: {COLOR_RESET}")
            try:
                with open(file_path, 'w') as f:
                    f.write(encrypted)
                print(f"{COLOR_SUCCESS}Encrypted text saved to {file_path}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}Error saving to file: {str(e)}{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error during encryption: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def quick_decrypt():
    """Decrypts text with a password."""
    print_banner()
    print(f"{COLOR_TITLE}Quick Decrypt (Password){COLOR_RESET}\n")
    print("This will decrypt text that was encrypted with a password.\n")
    
    # Get encrypted text
    encrypted = input(f"{COLOR_PROMPT}Enter the encrypted text: {COLOR_RESET}")
    if not encrypted:
        print(f"{COLOR_ERROR}Error: No encrypted text entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Check if it's a file path
    if os.path.exists(encrypted):
        try:
            with open(encrypted, 'r') as f:
                encrypted = f.read().strip()
            print(f"{COLOR_INFO}Loaded encrypted text from file: {encrypted}{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_ERROR}Error reading file: {str(e)}{COLOR_RESET}")
            wait_for_key()
            return
    
    # Get password
    password = getpass.getpass(f"{COLOR_PROMPT}Enter the password: {COLOR_RESET}")
    if not password:
        print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    try:
        print(f"\n{COLOR_INFO}Decrypting...{COLOR_RESET}")
        decrypted = decrypt_with_password(encrypted, password)
        
        print(f"\n{COLOR_SUCCESS}Decryption successful!{COLOR_RESET}")
        print(f"\n{COLOR_HIGHLIGHT}Decrypted text:{COLOR_RESET}")
        print(decrypted)
        
        # Add to history
        add_to_history("decrypt", {
            "method": "password"
        })
        
        # Ask if user wants to save to file
        save_to_file = input(f"\n{COLOR_PROMPT}Save to file? (y/n): {COLOR_RESET}").lower()
        if save_to_file == 'y':
            file_path = input(f"{COLOR_PROMPT}Enter file path: {COLOR_RESET}")
            try:
                with open(file_path, 'w') as f:
                    f.write(decrypted)
                print(f"{COLOR_SUCCESS}Decrypted text saved to {file_path}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}Error saving to file: {str(e)}{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error during decryption: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def encrypt_with_public_key_menu():
    """Encrypts text with a public key."""
    print_banner()
    print(f"{COLOR_TITLE}Encrypt with Public Key{COLOR_RESET}\n")
    print("This will encrypt your text with someone's public key.")
    print("Only the owner of the corresponding private key can decrypt it.\n")
    
    # Get list of keys
    keys = list_keys()
    public_keys = [k for k in keys if k.get("has_public", False)]
    
    if not public_keys:
        print(f"{COLOR_ERROR}Error: No public keys found.{COLOR_RESET}")
        print("Please import or generate a key pair first.")
        wait_for_key()
        return
    
    # Display available keys
    print(f"{COLOR_INFO}Available public keys:{COLOR_RESET}")
    for i, key in enumerate(public_keys, 1):
        print(f"{COLOR_MENU}{i}. {key.get('name')} - {key.get('description', 'No description')}{COLOR_RESET}")
    
    # Select key
    try:
        selection = int(input(f"\n{COLOR_PROMPT}Select a key (number): {COLOR_RESET}"))
        if selection < 1 or selection > len(public_keys):
            print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
            wait_for_key()
            return
        
        selected_key = public_keys[selection - 1]
    except ValueError:
        print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get plaintext
    plaintext = input(f"\n{COLOR_PROMPT}Enter the text to encrypt: {COLOR_RESET}")
    if not plaintext:
        print(f"{COLOR_ERROR}Error: No text entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    try:
        print(f"\n{COLOR_INFO}Encrypting...{COLOR_RESET}")
        
        # Load the public key
        public_key_pem = load_key(selected_key.get("name"), "public")
        
        # Encrypt the plaintext
        encrypted = hybrid_encrypt(plaintext, public_key_pem)
        
        print(f"\n{COLOR_SUCCESS}Encryption successful!{COLOR_RESET}")
        print(f"\n{COLOR_HIGHLIGHT}Encrypted text:{COLOR_RESET}")
        print(encrypted)
        
        # Add to history
        add_to_history("encrypt", {
            "method": "public_key",
            "recipient": selected_key.get("name"),
            "plaintext": plaintext
        })
        
        # Ask if user wants to save to file
        save_to_file = input(f"\n{COLOR_PROMPT}Save to file? (y/n): {COLOR_RESET}").lower()
        if save_to_file == 'y':
            file_path = input(f"{COLOR_PROMPT}Enter file path: {COLOR_RESET}")
            try:
                with open(file_path, 'w') as f:
                    f.write(encrypted)
                print(f"{COLOR_SUCCESS}Encrypted text saved to {file_path}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}Error saving to file: {str(e)}{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error during encryption: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def decrypt_with_private_key_menu():
    """Decrypts text with a private key."""
    print_banner()
    print(f"{COLOR_TITLE}Decrypt with Private Key{COLOR_RESET}\n")
    print("This will decrypt text that was encrypted with your public key.\n")
    
    # Get list of keys
    keys = list_keys()
    private_keys = [k for k in keys if k.get("has_private", False)]
    
    if not private_keys:
        print(f"{COLOR_ERROR}Error: No private keys found.{COLOR_RESET}")
        print("Please import or generate a key pair first.")
        wait_for_key()
        return
    
    # Display available keys
    print(f"{COLOR_INFO}Available private keys:{COLOR_RESET}")
    for i, key in enumerate(private_keys, 1):
        print(f"{COLOR_MENU}{i}. {key.get('name')} - {key.get('description', 'No description')}{COLOR_RESET}")
    
    # Select key
    try:
        selection = int(input(f"\n{COLOR_PROMPT}Select a key (number): {COLOR_RESET}"))
        if selection < 1 or selection > len(private_keys):
            print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
            wait_for_key()
            return
        
        selected_key = private_keys[selection - 1]
    except ValueError:
        print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get encrypted text
    encrypted = input(f"\n{COLOR_PROMPT}Enter the encrypted text: {COLOR_RESET}")
    if not encrypted:
        print(f"{COLOR_ERROR}Error: No encrypted text entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Check if it's a file path
    if os.path.exists(encrypted):
        try:
            with open(encrypted, 'r') as f:
                encrypted = f.read().strip()
            print(f"{COLOR_INFO}Loaded encrypted text from file: {encrypted}{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_ERROR}Error reading file: {str(e)}{COLOR_RESET}")
            wait_for_key()
            return
    
    # Check if key is encrypted and get password if needed
    if selected_key.get("private_key_encrypted", False):
        password = getpass.getpass(f"{COLOR_PROMPT}Enter the password for the private key: {COLOR_RESET}")
        if not password:
            print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
            wait_for_key()
            return
    else:
        password = None
    
    try:
        print(f"\n{COLOR_INFO}Decrypting...{COLOR_RESET}")
        
        # Load the private key
        private_key_pem = load_key(selected_key.get("name"), "private", password)
        
        # Decrypt the ciphertext
        decrypted = hybrid_decrypt(encrypted, private_key_pem)
        
        print(f"\n{COLOR_SUCCESS}Decryption successful!{COLOR_RESET}")
        print(f"\n{COLOR_HIGHLIGHT}Decrypted text:{COLOR_RESET}")
        print(decrypted)
        
        # Add to history
        add_to_history("decrypt", {
            "method": "private_key",
            "key_name": selected_key.get("name")
        })
        
        # Ask if user wants to save to file
        save_to_file = input(f"\n{COLOR_PROMPT}Save to file? (y/n): {COLOR_RESET}").lower()
        if save_to_file == 'y':
            file_path = input(f"{COLOR_PROMPT}Enter file path: {COLOR_RESET}")
            try:
                with open(file_path, 'w') as f:
                    f.write(decrypted)
                print(f"{COLOR_SUCCESS}Decrypted text saved to {file_path}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}Error saving to file: {str(e)}{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error during decryption: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def generate_new_keypair_menu():
    """Generates a new key pair."""
    print_banner()
    print(f"{COLOR_TITLE}Generate New Key Pair{COLOR_RESET}")
    print("This will create a new public/private key pair for secure communication.")
    print("The private key should be kept secret, while the public key can be shared.\n")
    
    # Get key details
    name = input(f"{COLOR_PROMPT}Enter a name for this key pair: {COLOR_RESET}")
    if not name:
        print(f"{COLOR_ERROR}Error: No name entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    description = input(f"{COLOR_PROMPT}Enter an optional description: {COLOR_RESET}")
    
    key_type = input(f"{COLOR_PROMPT}Key type (rsa/curve25519) [default: rsa]: {COLOR_RESET}").lower()
    if not key_type:
        key_type = "rsa"
    
    if key_type not in ["rsa", "curve25519"]:
        print(f"{COLOR_ERROR}Error: Invalid key type. Must be 'rsa' or 'curve25519'.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get password
    password = getpass.getpass(f"\n{COLOR_PROMPT}Enter a strong password to protect your private key: {COLOR_RESET}")
    if not password:
        print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    confirm_password = getpass.getpass(f"{COLOR_PROMPT}Confirm password: {COLOR_RESET}")
    if password != confirm_password:
        print(f"{COLOR_ERROR}Error: Passwords do not match.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Check if key already exists
    keys = list_keys()
    if any(k.get("name") == name for k in keys):
        confirm = input(f"\n{COLOR_WARNING}A key with the name '{name}' already exists. Overwrite? (y/n): {COLOR_RESET}").lower()
        if confirm != 'y':
            print(f"{COLOR_INFO}Operation cancelled.{COLOR_RESET}")
            wait_for_key()
            return
    
    try:
        print(f"\n{COLOR_INFO}Generating {key_type.upper()} key pair...{COLOR_RESET}")
        
        # Generate the key pair
        private_key, public_key = generate_keypair(key_type)
        
        # Save the key pair
        success = save_keypair(private_key, public_key, name, password, description)
        
        if success:
            print(f"\n{COLOR_SUCCESS}Key pair generated and saved successfully!{COLOR_RESET}")
            
            # Add to history
            add_to_history("generate", {
                "key_name": name,
                "key_type": key_type
            })
        else:
            print(f"\n{COLOR_ERROR}Failed to save key pair.{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error generating key pair: {str(e)}{COLOR_RESET}")
        print(f"\n{COLOR_ERROR}Failed to save key pair.{COLOR_RESET}")
    
    wait_for_key()

def view_keys_menu():
    """Displays all available keys."""
    print_banner()
    print(f"{COLOR_TITLE}View My Keys{COLOR_RESET}\n")
    
    # Get list of keys
    keys = list_keys()
    
    if not keys:
        print(f"{COLOR_INFO}No keys found.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Display keys
    print(f"{COLOR_INFO}Found {len(keys)} key(s):{COLOR_RESET}\n")
    for i, key in enumerate(keys, 1):
        name = key.get("name", "Unknown")
        key_type = key.get("type", "Unknown")
        created = key.get("created", "")
        
        if created:
            try:
                created = datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                created = "Unknown"
        else:
            created = "Unknown"
        
        description = key.get("description", "")
        
        status = []
        if key.get("has_public", False):
            status.append("Public Key Available")
        if key.get("has_private", False):
            if key.get("private_key_encrypted", False):
                status.append("Private Key Protected")
            else:
                status.append("Private Key Available")
        
        print(f"{COLOR_HIGHLIGHT}{i}. {name} ({key_type}){COLOR_RESET}")
        print(f"   {COLOR_INFO}Created: {created}{COLOR_RESET}")
        if description:
            print(f"   {COLOR_INFO}Description: {description}{COLOR_RESET}")
        print(f"   {COLOR_INFO}Status: {', '.join(status)}{COLOR_RESET}")
        print("")
    
    wait_for_key()

def import_key_menu():
    """Imports a key from a file."""
    print_banner()
    print(f"{COLOR_TITLE}Import Key{COLOR_RESET}\n")
    print("This will import a key from a PEM file.\n")
    
    # Get key details
    name = input(f"{COLOR_PROMPT}Enter a name for this key: {COLOR_RESET}")
    if not name:
        print(f"{COLOR_ERROR}Error: No name entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    description = input(f"{COLOR_PROMPT}Enter an optional description: {COLOR_RESET}")
    
    key_path = input(f"{COLOR_PROMPT}Enter the path to the key file: {COLOR_RESET}")
    if not key_path or not os.path.exists(key_path):
        print(f"{COLOR_ERROR}Error: Invalid file path.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Read key file
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
    except Exception as e:
        print(f"{COLOR_ERROR}Error reading key file: {str(e)}{COLOR_RESET}")
        wait_for_key()
        return
    
    # Determine key type
    key_type = ""
    if b"PRIVATE KEY" in key_data:
        key_type = "private"
        
        # Get password for private key
        password = getpass.getpass(f"{COLOR_PROMPT}Enter a password to protect the private key: {COLOR_RESET}")
        if not password:
            print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
            wait_for_key()
            return
        
        confirm_password = getpass.getpass(f"{COLOR_PROMPT}Confirm password: {COLOR_RESET}")
        if password != confirm_password:
            print(f"{COLOR_ERROR}Error: Passwords do not match.{COLOR_RESET}")
            wait_for_key()
            return
    elif b"PUBLIC KEY" in key_data:
        key_type = "public"
        password = None
    else:
        print(f"{COLOR_ERROR}Error: File does not appear to be a valid PEM key.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Check if key already exists
    keys = list_keys()
    if any(k.get("name") == name and k.get(f"has_{key_type}", False) for k in keys):
        confirm = input(f"{COLOR_WARNING}A {key_type} key with the name '{name}' already exists. Overwrite? (y/n): {COLOR_RESET}").lower()
        if confirm != 'y':
            print(f"{COLOR_INFO}Operation cancelled.{COLOR_RESET}")
            wait_for_key()
            return
    
    try:
        # Import the key
        if key_type == "private":
            # Encrypt and save the private key
            encrypted_key_data = encrypt_private_key(key_data, password)
            
            # Create or update metadata
            metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                metadata["has_private"] = True
                metadata["private_key_encrypted"] = True
                if description and not metadata.get("description"):
                    metadata["description"] = description
            else:
                metadata = {
                    "name": name,
                    "description": description,
                    "created": datetime.now().isoformat(),
                    "type": "RSA" if b"RSA" in key_data else "Ed25519",
                    "has_private": True,
                    "has_public": False,
                    "private_key_encrypted": True
                }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Save encrypted private key
            private_key_path = os.path.join(KEY_DIRECTORY, f"{name}.private.pem")
            with open(private_key_path, 'wb') as f:
                f.write(encrypted_key_data)
        else:
            # Save public key
            metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                metadata["has_public"] = True
                if description and not metadata.get("description"):
                    metadata["description"] = description
            else:
                metadata = {
                    "name": name,
                    "description": description,
                    "created": datetime.now().isoformat(),
                    "type": "RSA" if b"RSA" in key_data else "Ed25519",
                    "has_private": False,
                    "has_public": True,
                    "private_key_encrypted": False
                }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Save public key
            public_key_path = os.path.join(KEY_DIRECTORY, f"{name}.public.pem")
            with open(public_key_path, 'wb') as f:
                f.write(key_data)
        
        # Add to history
        add_to_history("import", {
            "key_name": name,
            "key_type": key_type
        })
        
        print(f"\n{COLOR_SUCCESS}{key_type.capitalize()} key '{name}' imported successfully!{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error importing key: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def export_key_menu():
    """Exports a key to a file."""
    print_banner()
    print(f"{COLOR_TITLE}Export Key{COLOR_RESET}\n")
    
    # Get list of keys
    keys = list_keys()
    
    if not keys:
        print(f"{COLOR_INFO}No keys found.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Display available keys
    print(f"{COLOR_INFO}Available keys:{COLOR_RESET}")
    for i, key in enumerate(keys, 1):
        name = key.get("name", "Unknown")
        key_type = key.get("type", "Unknown")
        
        status = []
        if key.get("has_public", False):
            status.append("Public")
        if key.get("has_private", False):
            status.append("Private")
        
        print(f"{COLOR_MENU}{i}. {name} ({key_type}) - {', '.join(status)}{COLOR_RESET}")
    
    # Select key
    try:
        selection = int(input(f"\n{COLOR_PROMPT}Select a key (number): {COLOR_RESET}"))
        if selection < 1 or selection > len(keys):
            print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
            wait_for_key()
            return
        
        selected_key = keys[selection - 1]
    except ValueError:
        print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Select key type to export
    available_types = []
    if selected_key.get("has_public", False):
        available_types.append("public")
    if selected_key.get("has_private", False):
        available_types.append("private")
    
    if len(available_types) > 1:
        print(f"\n{COLOR_INFO}Select key type to export:{COLOR_RESET}")
        for i, key_type in enumerate(available_types, 1):
            print(f"{COLOR_MENU}{i}. {key_type.capitalize()} Key{COLOR_RESET}")
        
        try:
            type_selection = int(input(f"\n{COLOR_PROMPT}Select type (number): {COLOR_RESET}"))
            if type_selection < 1 or type_selection > len(available_types):
                print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
                wait_for_key()
                return
            
            key_type = available_types[type_selection - 1]
        except ValueError:
            print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
            wait_for_key()
            return
    elif len(available_types) == 1:
        key_type = available_types[0]
    else:
        print(f"{COLOR_ERROR}Error: No keys available for export.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get export path
    export_path = input(f"\n{COLOR_PROMPT}Enter the path to save the key: {COLOR_RESET}")
    if not export_path:
        print(f"{COLOR_ERROR}Error: No path entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get password if exporting private key
    password = None
    if key_type == "private" and selected_key.get("private_key_encrypted", False):
        password = getpass.getpass(f"{COLOR_PROMPT}Enter the password for the private key: {COLOR_RESET}")
        if not password:
            print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
            wait_for_key()
            return
    
    try:
        # Load the key
        key_path = os.path.join(KEY_DIRECTORY, f"{selected_key.get('name')}.{key_type}.pem")
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # If it's an encrypted private key, decrypt it
        if key_type == "private" and selected_key.get("private_key_encrypted", False):
            try:
                key_data = decrypt_private_key(key_data, password)
            except ValueError as e:
                print(f"{COLOR_ERROR}Error decrypting private key: {str(e)}{COLOR_RESET}")
                wait_for_key()
                return
        
        # Write to export path
        with open(export_path, 'wb') as f:
            f.write(key_data)
        
        # Add to history
        add_to_history("export", {
            "key_name": selected_key.get("name"),
            "key_type": key_type
        })
        
        print(f"\n{COLOR_SUCCESS}{key_type.capitalize()} key '{selected_key.get('name')}' exported successfully to {export_path}{COLOR_RESET}")
        
        # Show warning for private keys
        if key_type == "private":
            print(f"\n{COLOR_WARNING}WARNING: You have exported a private key. Keep this file secure and do not share it with others.{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error exporting key: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def delete_key_menu():
    """Deletes a key."""
    print_banner()
    print(f"{COLOR_TITLE}Delete Key{COLOR_RESET}\n")
    
    # Get list of keys
    keys = list_keys()
    
    if not keys:
        print(f"{COLOR_INFO}No keys found.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Display available keys
    print(f"{COLOR_INFO}Available keys:{COLOR_RESET}")
    for i, key in enumerate(keys, 1):
        name = key.get("name", "Unknown")
        key_type = key.get("type", "Unknown")
        
        status = []
        if key.get("has_public", False):
            status.append("Public")
        if key.get("has_private", False):
            status.append("Private")
        
        print(f"{COLOR_MENU}{i}. {name} ({key_type}) - {', '.join(status)}{COLOR_RESET}")
    
    # Select key
    try:
        selection = int(input(f"\n{COLOR_PROMPT}Select a key to delete (number): {COLOR_RESET}"))
        if selection < 1 or selection > len(keys):
            print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
            wait_for_key()
            return
        
        selected_key = keys[selection - 1]
    except ValueError:
        print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Determine what to delete
    options = ["Entire key pair"]
    if selected_key.get("has_public", False) and selected_key.get("has_private", False):
        options.extend(["Public key only", "Private key only"])
    
    if len(options) > 1:
        print(f"\n{COLOR_INFO}Select what to delete:{COLOR_RESET}")
        for i, option in enumerate(options, 1):
            print(f"{COLOR_MENU}{i}. {option}{COLOR_RESET}")
        
        try:
            option_selection = int(input(f"\n{COLOR_PROMPT}Select option (number): {COLOR_RESET}"))
            if option_selection < 1 or option_selection > len(options):
                print(f"{COLOR_ERROR}Error: Invalid selection.{COLOR_RESET}")
                wait_for_key()
                return
            
            option = options[option_selection - 1]
        except ValueError:
            print(f"{COLOR_ERROR}Error: Please enter a number.{COLOR_RESET}")
            wait_for_key()
            return
        
        if option == "Public key only":
            key_type = "public"
        elif option == "Private key only":
            key_type = "private"
        else:
            key_type = "both"
    else:
        key_type = "both"
    
    # Confirm deletion
    confirm_message = f"Are you sure you want to delete the {key_type} key for '{selected_key.get('name')}'?"
    if key_type == "both":
        confirm_message = f"Are you sure you want to delete the entire key pair '{selected_key.get('name')}'?"
    
    confirm = input(f"\n{COLOR_WARNING}{confirm_message} (y/n): {COLOR_RESET}").lower()
    if confirm != 'y':
        print(f"{COLOR_INFO}Operation cancelled.{COLOR_RESET}")
        wait_for_key()
        return
    
    try:
        # Delete the key
        name = selected_key.get("name")
        metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
        private_key_path = os.path.join(KEY_DIRECTORY, f"{name}.private.pem")
        public_key_path = os.path.join(KEY_DIRECTORY, f"{name}.public.pem")
        
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
        
        # Add to history
        add_to_history("delete", {
            "key_name": name,
            "key_type": key_type
        })
        
        print(f"\n{COLOR_SUCCESS}Key deletion successful!{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error deleting key: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def view_history_menu():
    """Displays the operation history."""
    print_banner()
    print(f"{COLOR_TITLE}Recent Activity{COLOR_RESET}\n")
    
    # Get history
    history = get_history()
    
    if not history:
        print(f"{COLOR_INFO}No history found.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Display history
    print(f"{COLOR_INFO}Found {len(history)} entries:{COLOR_RESET}\n")
    for i, entry in enumerate(reversed(history), 1):
        timestamp = datetime.fromisoformat(entry.get("timestamp", "")).strftime("%Y-%m-%d %H:%M:%S")
        operation = entry.get("operation", "").capitalize()
        
        details = ""
        if operation == "Encrypt":
            if entry.get("method") == "password":
                details = "with password"
            else:
                details = f"for recipient: {entry.get('recipient', 'unknown')}"
        elif operation == "Decrypt":
            if entry.get("method") == "password":
                details = "with password"
            else:
                details = f"using key: {entry.get('key_name', 'unknown')}"
        elif operation == "Generate":
            details = f"key pair: {entry.get('key_name', 'unknown')}"
        elif operation == "Import":
            details = f"{entry.get('key_type', 'unknown')} key: {entry.get('key_name', 'unknown')}"
        elif operation == "Export":
            details = f"{entry.get('key_type', 'unknown')} key: {entry.get('key_name', 'unknown')}"
        elif operation == "Delete":
            details = f"{entry.get('key_type', 'unknown')} key: {entry.get('key_name', 'unknown')}"
        
        print(f"{COLOR_MENU}{i}. [{timestamp}] {operation} {details}{COLOR_RESET}")
    
    # Ask if user wants to clear history
    clear = input(f"\n{COLOR_PROMPT}Clear history? (y/n): {COLOR_RESET}").lower()
    if clear == 'y':
        confirm = input(f"{COLOR_WARNING}Are you sure you want to clear all history? (y/n): {COLOR_RESET}").lower()
        if confirm == 'y':
            # Clear history file
            if os.path.exists(HISTORY_FILE):
                try:
                    os.remove(HISTORY_FILE)
                    print(f"{COLOR_SUCCESS}History cleared.{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}Error clearing history: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def check_system_requirements():
    """Checks if the system meets the requirements."""
    print_banner()
    print(f"{COLOR_TITLE}System Requirements Check{COLOR_RESET}\n")
    
    # Check Python version
    python_version = platform.python_version()
    python_ok = tuple(map(int, python_version.split('.'))) >= (3, 6, 0)
    
    print(f"{COLOR_INFO}Python version: {python_version}{COLOR_RESET}")
    print(f"{COLOR_INFO}Required: 3.6.0 or higher{COLOR_RESET}")
    print(f"{COLOR_INFO}Status: {COLOR_SUCCESS if python_ok else COLOR_ERROR}{'OK' if python_ok else 'NOT OK'}{COLOR_RESET}")
    print("")
    
    # Check cryptography module
    crypto_version = "Not installed"
    crypto_ok = False
    try:
        import cryptography
        crypto_version = cryptography.__version__
        crypto_ok = True
    except ImportError:
        pass
    
    print(f"{COLOR_INFO}Cryptography module: {crypto_version}{COLOR_RESET}")
    print(f"{COLOR_INFO}Required: Any version{COLOR_RESET}")
    print(f"{COLOR_INFO}Status: {COLOR_SUCCESS if crypto_ok else COLOR_ERROR}{'OK' if crypto_ok else 'NOT OK'}{COLOR_RESET}")
    print("")
    
    # Check Argon2 module
    argon2_version = "Not installed"
    argon2_ok = False
    try:
        import argon2
        argon2_version = argon2.__version__
        argon2_ok = True
    except ImportError:
        pass
    
    print(f"{COLOR_INFO}Argon2 module: {argon2_version}{COLOR_RESET}")
    print(f"{COLOR_INFO}Required: Optional (recommended){COLOR_RESET}")
    print(f"{COLOR_INFO}Status: {COLOR_SUCCESS if argon2_ok else COLOR_WARNING}{'OK' if argon2_ok else 'OPTIONAL'}{COLOR_RESET}")
    print("")
    
    # Check operating system
    os_name = platform.system()
    os_version = platform.version()
    
    print(f"{COLOR_INFO}Operating system: {os_name} {os_version}{COLOR_RESET}")
    print(f"{COLOR_INFO}Required: Any{COLOR_RESET}")
    print(f"{COLOR_INFO}Status: {COLOR_SUCCESS}OK{COLOR_RESET}")
    print("")
    
    # Overall status
    if python_ok and crypto_ok:
        print(f"{COLOR_SUCCESS}Overall status: OK{COLOR_RESET}")
        print(f"{COLOR_SUCCESS}Your system meets all the requirements to run C-Crypt Pro.{COLOR_RESET}")
    else:
        print(f"{COLOR_ERROR}Overall status: NOT OK{COLOR_RESET}")
        print(f"{COLOR_ERROR}Your system does not meet all the requirements to run C-Crypt Pro.{COLOR_RESET}")
        
        if not python_ok:
            print(f"{COLOR_ERROR}- Please upgrade Python to version 3.6.0 or higher.{COLOR_RESET}")
        
        if not crypto_ok:
            print(f"{COLOR_ERROR}- Please install the cryptography module with: pip install cryptography{COLOR_RESET}")
    
    wait_for_key()

def show_help():
    """Displays help and documentation."""
    print_banner()
    print(f"{COLOR_TITLE}Help & Documentation{COLOR_RESET}\n")
    
    print(f"{COLOR_INFO}C-Crypt Pro is an advanced encryption tool that provides secure encryption and decryption{COLOR_RESET}")
    print(f"{COLOR_INFO}of text and files using both password-based and public key cryptography.{COLOR_RESET}\n")
    
    print(f"{COLOR_HIGHLIGHT}Key Features:{COLOR_RESET}")
    print(f"{COLOR_INFO}- Password-based encryption using AES-256-GCM with Argon2id key derivation{COLOR_RESET}")
    print(f"{COLOR_INFO}- Public key cryptography using RSA-4096 and Curve25519{COLOR_RESET}")
    print(f"{COLOR_INFO}- Hybrid encryption for secure communication{COLOR_RESET}")
    print(f"{COLOR_INFO}- Key management (generation, import, export, deletion){COLOR_RESET}")
    print(f"{COLOR_INFO}- Operation history tracking{COLOR_RESET}\n")
    
    print(f"{COLOR_HIGHLIGHT}Usage Tips:{COLOR_RESET}")
    print(f"{COLOR_INFO}1. For quick encryption/decryption, use password-based encryption.{COLOR_RESET}")
    print(f"{COLOR_INFO}2. For secure communication, generate a key pair and share your public key.{COLOR_RESET}")
    print(f"{COLOR_INFO}3. Keep your private keys secure and protected with strong passwords.{COLOR_RESET}")
    print(f"{COLOR_INFO}4. Regularly back up your keys to prevent data loss.{COLOR_RESET}")
    print(f"{COLOR_INFO}5. Use strong, unique passwords for key protection and encryption.{COLOR_RESET}\n")
    
    print(f"{COLOR_HIGHLIGHT}Command Line Arguments:{COLOR_RESET}")
    print(f"{COLOR_INFO}  -h, --help            Show this help message and exit{COLOR_RESET}")
    print(f"{COLOR_INFO}  -e, --encrypt         Encrypt text with a password{COLOR_RESET}")
    print(f"{COLOR_INFO}  -d, --decrypt         Decrypt text with a password{COLOR_RESET}")
    print(f"{COLOR_INFO}  -t, --text TEXT       Text to encrypt or decrypt{COLOR_RESET}")
    print(f"{COLOR_INFO}  -p, --password PASS   Password for encryption or decryption{COLOR_RESET}")
    print(f"{COLOR_INFO}  -i, --input FILE      Input file{COLOR_RESET}")
    print(f"{COLOR_INFO}  -o, --output FILE     Output file{COLOR_RESET}")
    print(f"{COLOR_INFO}  -k, --key KEY         Key name for public key encryption/decryption{COLOR_RESET}")
    print(f"{COLOR_INFO}  -g, --generate NAME   Generate a new key pair with the given name{COLOR_RESET}")
    print(f"{COLOR_INFO}  -l, --list            List all available keys{COLOR_RESET}")
    print(f"{COLOR_INFO}  -v, --version         Show version information and exit{COLOR_RESET}\n")
    
    print(f"{COLOR_HIGHLIGHT}Examples:{COLOR_RESET}")
    print(f"{COLOR_INFO}  c-crypt-pro.py -e -t \"Hello, world!\" -p \"mypassword\"{COLOR_RESET}")
    print(f"{COLOR_INFO}  c-crypt-pro.py -d -i encrypted.txt -p \"mypassword\"{COLOR_RESET}")
    print(f"{COLOR_INFO}  c-crypt-pro.py -g mykey{COLOR_RESET}")
    print(f"{COLOR_INFO}  c-crypt-pro.py -l{COLOR_RESET}\n")
    
    print(f"{COLOR_INFO}For more information, visit: https://github.com/Bell-O/c-crypt-pro{COLOR_RESET}")
    
    wait_for_key()

def decrypt_flightcode():
    """Decrypts a FlightCode file."""
    print_banner()
    print(f"{COLOR_TITLE}Decrypt FlightCode File{COLOR_RESET}\n")
    print("This will decrypt a file encrypted with the FlightCode format.\n")
    
    # Get file path
    file_path = input(f"{COLOR_PROMPT}Enter the path to the FlightCode file: {COLOR_RESET}")
    if not file_path or not os.path.exists(file_path):
        print(f"{COLOR_ERROR}Error: Invalid file path.{COLOR_RESET}")
        wait_for_key()
        return
    
    # Get password
    password = getpass.getpass(f"{COLOR_PROMPT}Enter the password: {COLOR_RESET}")
    if not password:
        print(f"{COLOR_ERROR}Error: No password entered.{COLOR_RESET}")
        wait_for_key()
        return
    
    try:
        # Read the file
        with open(file_path, 'r') as f:
            encrypted = f.read().strip()
        
        # Check if it's a FlightCode file
        if not encrypted.startswith("FC01:"):
            print(f"{COLOR_ERROR}Error: Not a valid FlightCode file.{COLOR_RESET}")
            wait_for_key()
            return
        
        # Remove the header
        encrypted = encrypted[5:]
        
        print(f"\n{COLOR_INFO}Decrypting...{COLOR_RESET}")
        
        # Decrypt the file
        decrypted = decrypt_with_password(encrypted, password)
        
        print(f"\n{COLOR_SUCCESS}Decryption successful!{COLOR_RESET}")
        print(f"\n{COLOR_HIGHLIGHT}Decrypted text:{COLOR_RESET}")
        print(decrypted)
        
        # Ask if user wants to save to file
        save_to_file = input(f"\n{COLOR_PROMPT}Save to file? (y/n): {COLOR_RESET}").lower()
        if save_to_file == 'y':
            output_path = input(f"{COLOR_PROMPT}Enter file path: {COLOR_RESET}")
            try:
                with open(output_path, 'w') as f:
                    f.write(decrypted)
                print(f"{COLOR_SUCCESS}Decrypted text saved to {output_path}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}Error saving to file: {str(e)}{COLOR_RESET}")
    
    except Exception as e:
        print(f"\n{COLOR_ERROR}Error decrypting file: {str(e)}{COLOR_RESET}")
    
    wait_for_key()

def parse_args():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION} - Advanced Encryption Tool")
    
    # Main operations
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt text with a password")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt text with a password")
    parser.add_argument("-t", "--text", help="Text to encrypt or decrypt")
    parser.add_argument("-p", "--password", help="Password for encryption or decryption")
    parser.add_argument("-i", "--input", help="Input file")
    parser.add_argument("-o", "--output", help="Output file")
    
    # Key operations
    parser.add_argument("-k", "--key", help="Key name for public key encryption/decryption")
    parser.add_argument("-g", "--generate", metavar="NAME", help="Generate a new key pair with the given name")
    parser.add_argument("-l", "--list", action="store_true", help="List all available keys")
    
    # Other
    parser.add_argument("-v", "--version", action="store_true", help="Show version information and exit")
    
    return parser.parse_args()

def handle_args(args):
    """Handles command line arguments."""
    # Show version
    if args.version:
        print(f"{COLOR_INFO}{APP_NAME} v{APP_VERSION}{COLOR_RESET}")
        return True
    
    # List keys
    if args.list:
        keys = list_keys()
        if not keys:
            print(f"{COLOR_INFO}No keys found.{COLOR_RESET}")
            return True
        
        print(f"{COLOR_INFO}Found {len(keys)} key(s):{COLOR_RESET}")
        for key in keys:
            name = key.get("name", "Unknown")
            key_type = key.get("type", "Unknown")
            
            status = []
            if key.get("has_public", False):
                status.append("Public Key Available")
            if key.get("has_private", False):
                if key.get("private_key_encrypted", False):
                    status.append("Private Key Protected")
                else:
                    status.append("Private Key Available")
            
            print(f"{COLOR_MENU}{name} ({key_type}) - {', '.join(status)}{COLOR_RESET}")
        
        return True
    
    # Generate key pair
    if args.generate:
        name = args.generate
        
        # Get password
        if not args.password:
            password = getpass.getpass(f"{COLOR_PROMPT}Enter a password to protect the private key: {COLOR_RESET}")
        else:
            password = args.password
        
        try:
            print(f"{COLOR_INFO}Generating RSA key pair...{COLOR_RESET}")
            
            # Generate the key pair
            private_key, public_key = generate_keypair()
            
            # Save the key pair
            success = save_keypair(private_key, public_key, name, password)
            
            if success:
                print(f"{COLOR_SUCCESS}Key pair '{name}' generated and saved successfully!{COLOR_RESET}")
                return True
            else:
                print(f"{COLOR_ERROR}Failed to save key pair.{COLOR_RESET}")
                return False
        
        except Exception as e:
            print(f"{COLOR_ERROR}Error generating key pair: {str(e)}{COLOR_RESET}")
            return False
    
    # Encrypt with password
    if args.encrypt and not args.key:
        # Get text to encrypt
        if args.text:
            plaintext = args.text
        elif args.input:
            try:
                with open(args.input, 'r') as f:
                    plaintext = f.read()
            except Exception as e:
                print(f"{COLOR_ERROR}Error reading input file: {str(e)}{COLOR_RESET}")
                return False
        else:
            print(f"{COLOR_ERROR}Error: No text or input file specified.{COLOR_RESET}")
            return False
        
        # Get password
        if not args.password:
            password = getpass.getpass(f"{COLOR_PROMPT}Enter a password: {COLOR_RESET}")
        else:
            password = args.password
        
        try:
            # Encrypt the plaintext
            encrypted = encrypt_with_password(plaintext, password)
            
            # Output the result
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(encrypted)
                    print(f"{COLOR_SUCCESS}Encrypted text saved to {args.output}{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}Error writing to output file: {str(e)}{COLOR_RESET}")
                    return False
            else:
                print(encrypted)
            
            return True
        
        except Exception as e:
            print(f"{COLOR_ERROR}Error during encryption: {str(e)}{COLOR_RESET}")
            return False
    
    # Decrypt with password
    if args.decrypt and not args.key:
        # Get text to decrypt
        if args.text:
            encrypted = args.text
        elif args.input:
            try:
                with open(args.input, 'r') as f:
                    encrypted = f.read().strip()
            except Exception as e:
                print(f"{COLOR_ERROR}Error reading input file: {str(e)}{COLOR_RESET}")
                return False
        else:
            print(f"{COLOR_ERROR}Error: No text or input file specified.{COLOR_RESET}")
            return False
        
        # Get password
        if not args.password:
            password = getpass.getpass(f"{COLOR_PROMPT}Enter the password: {COLOR_RESET}")
        else:
            password = args.password
        
        try:
            # Decrypt the ciphertext
            decrypted = decrypt_with_password(encrypted, password)
            
            # Output the result
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(decrypted)
                    print(f"{COLOR_SUCCESS}Decrypted text saved to {args.output}{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}Error writing to output file: {str(e)}{COLOR_RESET}")
                    return False
            else:
                print(decrypted)
            
            return True
        
        except Exception as e:
            print(f"{COLOR_ERROR}Error during decryption: {str(e)}{COLOR_RESET}")
            return False
    
    # Encrypt with public key
    if args.encrypt and args.key:
        # Get text to encrypt
        if args.text:
            plaintext = args.text
        elif args.input:
            try:
                with open(args.input, 'r') as f:
                    plaintext = f.read()
            except Exception as e:
                print(f"{COLOR_ERROR}Error reading input file: {str(e)}{COLOR_RESET}")
                return False
        else:
            print(f"{COLOR_ERROR}Error: No text or input file specified.{COLOR_RESET}")
            return False
        
        try:
            # Load the public key
            public_key_pem = load_key(args.key, "public")
            
            # Encrypt the plaintext
            encrypted = hybrid_encrypt(plaintext, public_key_pem)
            
            # Output the result
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(encrypted)
                    print(f"{COLOR_SUCCESS}Encrypted text saved to {args.output}{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}Error writing to output file: {str(e)}{COLOR_RESET}")
                    return False
            else:
                print(encrypted)
            
            return True
        
        except Exception as e:
            print(f"{COLOR_ERROR}Error during encryption: {str(e)}{COLOR_RESET}")
            return False
    
    # Decrypt with private key
    if args.decrypt and args.key:
        # Get text to decrypt
        if args.text:
            encrypted = args.text
        elif args.input:
            try:
                with open(args.input, 'r') as f:
                    encrypted = f.read().strip()
            except Exception as e:
                print(f"{COLOR_ERROR}Error reading input file: {str(e)}{COLOR_RESET}")
                return False
        else:
            print(f"{COLOR_ERROR}Error: No text or input file specified.{COLOR_RESET}")
            return False
        
        # Get password if needed
        password = None
        keys = list_keys()
        key = next((k for k in keys if k.get("name") == args.key), None)
        
        if key and key.get("private_key_encrypted", False):
            if not args.password:
                password = getpass.getpass(f"{COLOR_PROMPT}Enter the password for the private key: {COLOR_RESET}")
            else:
                password = args.password
        
        try:
            # Load the private key
            private_key_pem = load_key(args.key, "private", password)
            
            # Decrypt the ciphertext
            decrypted = hybrid_decrypt(encrypted, private_key_pem)
            
            # Output the result
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(decrypted)
                    print(f"{COLOR_SUCCESS}Decrypted text saved to {args.output}{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}Error writing to output file: {str(e)}{COLOR_RESET}")
                    return False
            else:
                print(decrypted)
            
            return True
        
        except Exception as e:
            print(f"{COLOR_ERROR}Error during decryption: {str(e)}{COLOR_RESET}")
            return False
    
    # No valid operation specified
    return False

def main():
    """Main function to run the application."""
    # Parse command line arguments
    args = parse_args()
    
    # Handle command line arguments if provided
    if len(sys.argv) > 1:
        if handle_args(args):
            sys.exit(0)
        else:
            sys.exit(1)
    
    # If no arguments provided, run interactive mode
    while True:
        print_banner()
        print_main_menu()
        
        try:
            choice = input(f"{COLOR_PROMPT}Enter your choice (0-13): {COLOR_RESET}")
            
            if choice == "0":
                print(f"\n{COLOR_INFO}Exiting C-Crypt Pro. Goodbye!{COLOR_RESET}")
                break
            elif choice == "1":
                quick_encrypt()
            elif choice == "2":
                quick_decrypt()
            elif choice == "3":
                encrypt_with_public_key_menu()
            elif choice == "4":
                decrypt_with_private_key_menu()
            elif choice == "5":
                generate_new_keypair_menu()
            elif choice == "6":
                view_keys_menu()
            elif choice == "7":
                import_key_menu()
            elif choice == "8":
                export_key_menu()
            elif choice == "9":
                delete_key_menu()
            elif choice == "10":
                view_history_menu()
            elif choice == "11":
                check_system_requirements()
            elif choice == "12":
                show_help()
            elif choice == "13":
                decrypt_flightcode()
            else:
                print(f"\n{COLOR_ERROR}Invalid choice. Please try again.{COLOR_RESET}")
                wait_for_key()
        
        except KeyboardInterrupt:
            print(f"\n\n{COLOR_WARNING}Operation cancelled by user.{COLOR_RESET}")
            wait_for_key()
        except Exception as e:
            print(f"\n{COLOR_ERROR}An unexpected error occurred: {str(e)}{COLOR_RESET}")
            print(f"{COLOR_ERROR}Error details:{COLOR_RESET}")
            traceback.print_exc()
            wait_for_key()

if __name__ == "__main__":
    main()