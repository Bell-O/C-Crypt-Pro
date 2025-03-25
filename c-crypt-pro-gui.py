#!/usr/bin/env python3
# C-Crypt Pro GUI
# Advanced Encryption Tool with High-Tech UI

import os
import sys
import base64
import json
import platform
import shutil
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import traceback

# Import Qt libraries
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                                QTextEdit, QComboBox, QTabWidget, QFileDialog,
                                QMessageBox, QFrame, QSplitter, QProgressBar,
                                QListWidget, QListWidgetItem, QStackedWidget,
                                QDialog, QScrollArea, QGridLayout, QGroupBox)
    from PyQt5.QtGui import QFont, QFontDatabase, QIcon, QPixmap, QPainter, QColor, QPen
    from PyQt5.QtCore import Qt, QSize, QTimer, QThread, pyqtSignal, QRect, QPoint
    import qdarkstyle
except ImportError:
    print("Error: Required GUI dependencies not found.")
    print("Please install them with: pip install PyQt5 qdarkstyle")
    sys.exit(1)

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
    print("Error: Required 'cryptography' module not found.")
    print("Install with: pip install cryptography")
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
APP_VERSION = "1.0.0"
APP_DIR = os.path.expanduser("~/.c-crypt-pro")
KEY_DIRECTORY = os.path.join(APP_DIR, "keys")
HISTORY_FILE = os.path.join(APP_DIR, "history.json")
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits
DEFAULT_KEY_TYPE = "rsa"

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
        print(f"Error saving key pair: {str(e)}")
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

# Worker thread for long operations
class CryptWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    
    def __init__(self, operation, args=None):
        super().__init__()
        self.operation = operation
        self.args = args or {}
    
    def run(self):
        try:
            result = None
            
            # Simulate progress for operations
            for i in range(101):
                self.progress.emit(i)
                time.sleep(0.01)  # Adjust based on operation complexity
                
                # For key generation, make it take longer
                if self.operation == "generate_keypair" and i > 50:
                    time.sleep(0.02)
            
            # Perform the actual operation
            if self.operation == "encrypt_password":
                result = encrypt_with_password(
                    self.args.get("plaintext", ""),
                    self.args.get("password", "")
                )
                
                # Add to history
                add_to_history("encrypt", {
                    "method": "password",
                    "plaintext": self.args.get("plaintext", "")
                })
                
            elif self.operation == "decrypt_password":
                result = decrypt_with_password(
                    self.args.get("encrypted", ""),
                    self.args.get("password", "")
                )
                
                # Add to history
                add_to_history("decrypt", {
                    "method": "password"
                })
                
            elif self.operation == "generate_keypair":
                try:
                    private_key, public_key = generate_keypair(
                        self.args.get("key_type", DEFAULT_KEY_TYPE)
                    )
                    
                    # Save the key pair
                    success = save_keypair(
                        private_key,
                        public_key,
                        self.args.get("name", ""),
                        self.args.get("password", ""),
                        self.args.get("description", "")
                    )
                    
                    if success:
                        # Add to history
                        add_to_history("generate", {
                            "key_name": self.args.get("name", ""),
                            "key_type": self.args.get("key_type", DEFAULT_KEY_TYPE)
                        })
                        
                        result = {
                            "success": True,
                            "name": self.args.get("name", "")
                        }
                    else:
                        result = {
                            "success": False,
                            "error": "Failed to save key pair"
                        }
                except Exception as e:
                    print(f"Error in generate_keypair: {str(e)}")
                    traceback.print_exc()
                    result = {
                        "success": False,
                        "error": str(e)
                    }
                
            elif self.operation == "encrypt_public_key":
                # Load the public key
                public_key_pem = load_key(
                    self.args.get("key_name", ""),
                    "public"
                )
                
                # Encrypt the plaintext
                result = hybrid_encrypt(
                    self.args.get("plaintext", ""),
                    public_key_pem
                )
                
                # Add to history
                add_to_history("encrypt", {
                    "method": "public_key",
                    "recipient": self.args.get("key_name", ""),
                    "plaintext": self.args.get("plaintext", "")
                })
                
            elif self.operation == "decrypt_private_key":
                # Load the private key
                private_key_pem = load_key(
                    self.args.get("key_name", ""),
                    "private",
                    self.args.get("password", "")
                )
                
                # Decrypt the ciphertext
                result = hybrid_decrypt(
                    self.args.get("encrypted", ""),
                    private_key_pem
                )
                
                # Add to history
                add_to_history("decrypt", {
                    "method": "private_key",
                    "key_name": self.args.get("key_name", "")
                })
            
            self.finished.emit(result)
            
        except Exception as e:
            print(f"Error in CryptWorker.run: {str(e)}")
            traceback.print_exc()
            self.error.emit(str(e))

# Custom UI components
import random
class BarcodeLine(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(30)
        self.bars = []
        self.generate_bars()
    
    def generate_bars(self):
        # Generate random barcode-like bars
        self.bars = []
        total_width = self.width() or 400
        bar_count = random.randint(20, 40)
        
        for i in range(bar_count):
            width = random.randint(1, 10)
            x = random.randint(0, total_width - width)
            self.bars.append((x, width))
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw bars
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(255, 255, 255))
        
        for x, width in self.bars:
            painter.drawRect(x, 0, width, self.height())
    
    def resizeEvent(self, event):
        self.generate_bars()
        super().resizeEvent(event)

class ScanLine(QWidget):
  def __init__(self, parent=None):
      super().__init__(parent)
      self.setFixedHeight(2)
      self.position = 0
      self.direction = 1
      self.timer = QTimer(self)
      self.timer.timeout.connect(self.update_position)
      self.timer.start(50)
  
  def update_position(self):
      self.position += self.direction
      if self.position >= 100 or self.position <= 0:
          self.direction *= -1
      self.update()
  
  def paintEvent(self, event):
      painter = QPainter(self)
      painter.setRenderHint(QPainter.Antialiasing)
      
      # Draw scan line
      pen = QPen(QColor(0, 200, 255))
      pen.setWidth(2)
      painter.setPen(pen)
      
      width = self.width()
      # Convert position to integer before using it in drawLine
      pos = int(width * self.position / 100)
      painter.drawLine(pos, 0, pos, self.height())

  def show_notification(self, message, error=False):
    notification = QLabel(message, self)
    notification.setStyleSheet(
        f"background-color: {'#ffcccc' if error else '#ccffcc'}; "
        "color: #000000; padding: 10px; border-radius: 5px;"
    )
    notification.setAlignment(Qt.AlignCenter)
    notification.setFixedWidth(300)
    
    # Position at the bottom center of the window
    notification.move(
        (self.width() - notification.width()) // 2,
        (self.height() - notification.height() - 20)
    )
    
    notification.show()
    
    # Auto-hide after 3 seconds
    QTimer.singleShot(3000, notification.hide)

class StatusBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(25)
        
        # Create layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 0, 5, 0)
        
        # Add status elements
        self.status_label = QLabel("SYSTEM READY")
        self.status_label.setStyleSheet("color: #00ff00;")
        
        self.coordinates = QLabel("N: 000000  E: 000000")
        self.coordinates.setStyleSheet("color: #aaaaaa;")
        
        self.time_label = QLabel("00:00:00")
        self.time_label.setStyleSheet("color: #aaaaaa;")
        
        # Add spacers and widgets
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.coordinates)
        layout.addStretch()
        layout.addWidget(self.time_label)
        
        # Start timer to update time
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        
        # Update coordinates periodically
        self.coord_timer = QTimer(self)
        self.coord_timer.timeout.connect(self.update_coordinates)
        self.coord_timer.start(5000)
        
        self.update_time()
        self.update_coordinates()
    
    def update_time(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.setText(current_time)
    
    def update_coordinates(self):
        # Generate random-looking coordinates
        n = random.randint(100000, 999999)
        e = random.randint(100000, 999999)
        self.coordinates.setText(f"N: {n}  E: {e}")
    
    def set_status(self, message, color="#00ff00"):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color};")

class ProgressMeter(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(15)
        self.value = 0
        self.max_value = 100
        self.color = QColor(0, 200, 255)
    
    def set_value(self, value):
        self.value = max(0, min(value, self.max_value))
        self.update()
    
    def set_color(self, color):
        self.color = color
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(30, 30, 30))
        painter.drawRect(0, 0, self.width(), self.height())
        
        # Draw progress
        if self.value > 0:
            width = int(self.width() * self.value / self.max_value)
            painter.setBrush(self.color)
            painter.drawRect(0, 0, width, self.height())
        
        # Draw segments
        painter.setPen(QPen(QColor(0, 0, 0, 50)))
        segment_width = self.width() / 20
        for i in range(1, 20):
            x = i * segment_width
            painter.drawLine(int(x), 0, int(x), self.height())

class PasswordDialog(QDialog):
    def __init__(self, key_name, parent=None):
        super().__init__(parent)
        self.key_name = key_name
        self.password = ""
        
        self.setWindowTitle("Enter Password")
        self.setFixedSize(400, 200)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Add header
        header = QLabel(f"ENTER PASSWORD FOR KEY: {key_name}")
        header.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold;")
        layout.addWidget(header)
        
        # Add barcode
        barcode = BarcodeLine()
        layout.addWidget(barcode)
        
        # Add password field
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        layout.addWidget(self.password_field)
        
        # Add buttons
        button_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("CANCEL")
        self.cancel_button.clicked.connect(self.reject)
        
        self.ok_button = QPushButton("CONFIRM")
        self.ok_button.clicked.connect(self.accept_password)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.ok_button)
        
        layout.addLayout(button_layout)
    
    def accept_password(self):
        self.password = self.password_field.text()
        self.accept()

# Main application window
class CCryptProGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Set up the main window
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1000, 700)
        
        # Set up the UI
        self.setup_ui()
        
        # Initialize the application
        self.initialize()
    
    def setup_ui(self):
        # Set up the central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Add header
        self.header = QWidget()
        self.header.setFixedHeight(60)
        self.header.setStyleSheet("background-color: #000000;")
        
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(10, 5, 10, 5)
        
        # Add logo/title
        title = QLabel(f"{APP_NAME} MONITORING SYSTEM")
        title.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold; font-family: 'Courier New', monospace;")
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        # Add coordinates display
        coords = QLabel("N: 617706  E: 697349")
        coords.setStyleSheet("color: #aaaaaa; font-family: 'Courier New', monospace;")
        header_layout.addWidget(coords)
        
        self.main_layout.addWidget(self.header)
        
        # Add barcode line
        self.barcode = BarcodeLine()
        self.main_layout.addWidget(self.barcode)
        
        # Add content area
        self.content = QWidget()
        self.content.setStyleSheet("background-color: #111111;")
        
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget for different functions
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #222222;
                color: #aaaaaa;
                padding: 8px 16px;
                border: 1px solid #444444;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #1a1a1a;
                color: #ffffff;
            }
        """)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_keys_tab()
        self.create_history_tab()
        
        content_layout.addWidget(self.tabs)
        self.main_layout.addWidget(self.content, 1)
        
        # Add status bar
        self.status_bar = StatusBar()
        self.main_layout.addWidget(self.status_bar)
    
    def create_dashboard_tab(self):
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        
        # Welcome message
        welcome = QLabel(f"WELCOME TO {APP_NAME}")
        welcome.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold; font-family: 'Courier New', monospace;")
        welcome.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome)
        
        # System status
        status_box = QGroupBox("SYSTEM STATUS")
        status_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        status_layout = QVBoxLayout(status_box)
        
        # Add status items
        status_items = [
            ("Encryption Engine", "ONLINE", "#00ff00"),
            ("Key Management", "ONLINE", "#00ff00"),
            ("Security Protocol", "LEVEL 3", "#00aaff"),
            ("System Integrity", "100%", "#00ff00")
        ]
        
        for label, value, color in status_items:
            item_layout = QHBoxLayout()
            
            label_widget = QLabel(label)
            label_widget.setStyleSheet("color: #aaaaaa;")
            
            value_widget = QLabel(value)
            value_widget.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            item_layout.addWidget(label_widget)
            item_layout.addStretch()
            item_layout.addWidget(value_widget)
            
            status_layout.addLayout(item_layout)
        
        layout.addWidget(status_box)
        
        # Quick actions
        actions_box = QGroupBox("QUICK ACTIONS")
        actions_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        actions_layout = QGridLayout(actions_box)
        
        # Create action buttons
        action_buttons = [
            ("ENCRYPT MESSAGE", self.tabs.setCurrentIndex, (1,)),
            ("DECRYPT MESSAGE", self.tabs.setCurrentIndex, (2,)),
            ("MANAGE KEYS", self.tabs.setCurrentIndex, (3,)),
            ("VIEW HISTORY", self.tabs.setCurrentIndex, (4,))
        ]
        
        for i, (text, func, args) in enumerate(action_buttons):
            button = QPushButton(text)
            button.setStyleSheet("""
                QPushButton {
                    background-color: #222222;
                    color: #ffffff;
                    border: 1px solid #444444;
                    padding: 10px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #333333;
                    border: 1px solid #666666;
                }
                QPushButton:pressed {
                    background-color: #444444;
                }
            """)
            
            # Connect button to function with arguments
            button.clicked.connect(lambda checked=False, f=func, a=args: f(*a))
            
            row, col = divmod(i, 2)
            actions_layout.addWidget(button, row, col)
        
        layout.addWidget(actions_box)
        layout.addStretch()
        
        self.tabs.addTab(dashboard, "DASHBOARD")
    
    def create_encrypt_tab(self):
        encrypt_tab = QWidget()
        layout = QVBoxLayout(encrypt_tab)
        
        # Create stacked widget for different encryption methods
        self.encrypt_stack = QStackedWidget()
        
        # Create method selection
        method_box = QGroupBox("ENCRYPTION METHOD")
        method_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        method_layout = QHBoxLayout(method_box)
        
        self.password_encrypt_btn = QPushButton("PASSWORD")
        self.password_encrypt_btn.setCheckable(True)
        self.password_encrypt_btn.setChecked(True)
        self.password_encrypt_btn.clicked.connect(lambda: self.encrypt_stack.setCurrentIndex(0))
        
        self.key_encrypt_btn = QPushButton("PUBLIC KEY")
        self.key_encrypt_btn.setCheckable(True)
        self.key_encrypt_btn.clicked.connect(lambda: self.encrypt_stack.setCurrentIndex(1))
        
        # Style buttons as toggle group
        for btn in [self.password_encrypt_btn, self.key_encrypt_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #222222;
                    color: #aaaaaa;
                    border: 1px solid #444444;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:checked {
                    background-color: #00aaff;
                    color: #ffffff;
                }
                QPushButton:hover:!checked {
                    background-color: #333333;
                }
            """)
        
        method_layout.addWidget(self.password_encrypt_btn)
        method_layout.addWidget(self.key_encrypt_btn)
        method_layout.addStretch()
        
        layout.addWidget(method_box)
        
        # Create password encryption page
        password_page = QWidget()
        password_layout = QVBoxLayout(password_page)
        
        # Message input
        password_layout.addWidget(QLabel("MESSAGE TO ENCRYPT:"))
        self.password_plaintext = QTextEdit()
        self.password_plaintext.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        password_layout.addWidget(self.password_plaintext)
        
        # Password input
        password_form = QHBoxLayout()
        password_form.addWidget(QLabel("PASSWORD:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        password_form.addWidget(self.password_input, 1)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        password_form.addWidget(QLabel("CONFIRM:"))
        password_form.addWidget(self.confirm_password_input, 1)
        
        password_layout.addLayout(password_form)
        
        # Encrypt button
        self.password_encrypt_button = QPushButton("ENCRYPT")
        self.password_encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #007700;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008800;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
        """)
        self.password_encrypt_button.clicked.connect(self.encrypt_with_password)
        password_layout.addWidget(self.password_encrypt_button)
        
        # Progress bar
        self.password_progress = ProgressMeter()
        self.password_progress.set_color(QColor(0, 200, 0))
        password_layout.addWidget(self.password_progress)
        
        # Result
        password_layout.addWidget(QLabel("ENCRYPTED MESSAGE:"))
        self.password_result = QTextEdit()
        self.password_result.setReadOnly(True)
        self.password_result.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        password_layout.addWidget(self.password_result)
        
        # Copy button
        self.password_copy_button = QPushButton("COPY TO CLIPBOARD")
        self.password_copy_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.password_copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.password_result.toPlainText()))
        password_layout.addWidget(self.password_copy_button)
        
        # Create public key encryption page
        key_page = QWidget()
        key_layout = QVBoxLayout(key_page)
        
        # Recipient selection
        key_layout.addWidget(QLabel("SELECT RECIPIENT (PUBLIC KEY):"))
        self.recipient_combo = QComboBox()
        self.recipient_combo.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                selection-background-color: #00aaff;
            }
        """)
        key_layout.addWidget(self.recipient_combo)
        
        # Message input
        key_layout.addWidget(QLabel("MESSAGE TO ENCRYPT:"))
        self.key_plaintext = QTextEdit()
        self.key_plaintext.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        key_layout.addWidget(self.key_plaintext)
        
        # Encrypt button
        self.key_encrypt_button = QPushButton("ENCRYPT")
        self.key_encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #007700;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008800;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
        """)
        self.key_encrypt_button.clicked.connect(self.encrypt_with_public_key)
        key_layout.addWidget(self.key_encrypt_button)
        
        # Progress bar
        self.key_progress = ProgressMeter()
        self.key_progress.set_color(QColor(0, 200, 0))
        key_layout.addWidget(self.key_progress)
        
        # Result
        key_layout.addWidget(QLabel("ENCRYPTED MESSAGE:"))
        self.key_result = QTextEdit()
        self.key_result.setReadOnly(True)
        self.key_result.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        key_layout.addWidget(self.key_result)
        
        # Copy button
        self.key_copy_button = QPushButton("COPY TO CLIPBOARD")
        self.key_copy_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.key_copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.key_result.toPlainText()))
        key_layout.addWidget(self.key_copy_button)
        
        # Add pages to stack
        self.encrypt_stack.addWidget(password_page)
        self.encrypt_stack.addWidget(key_page)
        
        layout.addWidget(self.encrypt_stack)
        
        self.tabs.addTab(encrypt_tab, "ENCRYPT")
    
    def create_decrypt_tab(self):
        decrypt_tab = QWidget()
        layout = QVBoxLayout(decrypt_tab)
        
        # Create stacked widget for different decryption methods
        self.decrypt_stack = QStackedWidget()
        
        # Create method selection
        method_box = QGroupBox("DECRYPTION METHOD")
        method_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        method_layout = QHBoxLayout(method_box)
        
        self.password_decrypt_btn = QPushButton("PASSWORD")
        self.password_decrypt_btn.setCheckable(True)
        self.password_decrypt_btn.setChecked(True)
        self.password_decrypt_btn.clicked.connect(lambda: self.decrypt_stack.setCurrentIndex(0))
        
        self.key_decrypt_btn = QPushButton("PRIVATE KEY")
        self.key_decrypt_btn.setCheckable(True)
        self.key_decrypt_btn.clicked.connect(lambda: self.decrypt_stack.setCurrentIndex(1))
        
        # Style buttons as toggle group
        for btn in [self.password_decrypt_btn, self.key_decrypt_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #222222;
                    color: #aaaaaa;
                    border: 1px solid #444444;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:checked {
                    background-color: #00aaff;
                    color: #ffffff;
                }
                QPushButton:hover:!checked {
                    background-color: #333333;
                }
            """)
        
        method_layout.addWidget(self.password_decrypt_btn)
        method_layout.addWidget(self.key_decrypt_btn)
        method_layout.addStretch()
        
        layout.addWidget(method_box)
        
        # Create password decryption page
        password_page = QWidget()
        password_layout = QVBoxLayout(password_page)
        
        # Encrypted message input
        password_layout.addWidget(QLabel("ENCRYPTED MESSAGE:"))
        self.password_encrypted = QTextEdit()
        self.password_encrypted.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        password_layout.addWidget(self.password_encrypted)
        
        # Password input
        password_form = QHBoxLayout()
        password_form.addWidget(QLabel("PASSWORD:"))
        self.decrypt_password_input = QLineEdit()
        self.decrypt_password_input.setEchoMode(QLineEdit.Password)
        self.decrypt_password_input.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        password_form.addWidget(self.decrypt_password_input, 1)
        
        password_layout.addLayout(password_form)
        
        # Decrypt button
        self.password_decrypt_button = QPushButton("DECRYPT")
        self.password_decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #770000;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #880000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        """)
        self.password_decrypt_button.clicked.connect(self.decrypt_with_password)
        password_layout.addWidget(self.password_decrypt_button)
        
        # Progress bar
        self.decrypt_password_progress = ProgressMeter()
        self.decrypt_password_progress.set_color(QColor(200, 0, 0))
        password_layout.addWidget(self.decrypt_password_progress)
        
        # Result
        password_layout.addWidget(QLabel("DECRYPTED MESSAGE:"))
        self.password_decrypted = QTextEdit()
        self.password_decrypted.setReadOnly(True)
        self.password_decrypted.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        password_layout.addWidget(self.password_decrypted)
        
        # Copy button
        self.password_decrypt_copy_button = QPushButton("COPY TO CLIPBOARD")
        self.password_decrypt_copy_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.password_decrypt_copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.password_decrypted.toPlainText()))
        password_layout.addWidget(self.password_decrypt_copy_button)
        
        # Create private key decryption page
        key_page = QWidget()
        key_layout = QVBoxLayout(key_page)
        
        # Private key selection
        key_layout.addWidget(QLabel("SELECT YOUR PRIVATE KEY:"))
        self.private_key_combo = QComboBox()
        self.private_key_combo.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                selection-background-color: #00aaff;
            }
        """)
        key_layout.addWidget(self.private_key_combo)
        
        # Encrypted message input
        key_layout.addWidget(QLabel("ENCRYPTED MESSAGE:"))
        self.key_encrypted = QTextEdit()
        self.key_encrypted.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        key_layout.addWidget(self.key_encrypted)
        
        # Decrypt button
        self.key_decrypt_button = QPushButton("DECRYPT")
        self.key_decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #770000;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #880000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        """)
        self.key_decrypt_button.clicked.connect(self.decrypt_with_private_key)
        key_layout.addWidget(self.key_decrypt_button)
        
        # Progress bar
        self.decrypt_key_progress = ProgressMeter()
        self.decrypt_key_progress.set_color(QColor(200, 0, 0))
        key_layout.addWidget(self.decrypt_key_progress)
        
        # Result
        key_layout.addWidget(QLabel("DECRYPTED MESSAGE:"))
        self.key_decrypted = QTextEdit()
        self.key_decrypted.setReadOnly(True)
        self.key_decrypted.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
        """)
        key_layout.addWidget(self.key_decrypted)
        
        # Copy button
        self.key_decrypt_copy_button = QPushButton("COPY TO CLIPBOARD")
        self.key_decrypt_copy_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.key_decrypt_copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.key_decrypted.toPlainText()))
        key_layout.addWidget(self.key_decrypt_copy_button)
        
        # Add pages to stack
        self.decrypt_stack.addWidget(password_page)
        self.decrypt_stack.addWidget(key_page)
        
        layout.addWidget(self.decrypt_stack)
        
        self.tabs.addTab(decrypt_tab, "DECRYPT")
    
    def create_keys_tab(self):
        keys_tab = QWidget()
        layout = QVBoxLayout(keys_tab)
        
        # Create stacked widget for different key operations
        self.keys_stack = QStackedWidget()
        
        # Create operation selection
        operation_box = QGroupBox("KEY OPERATIONS")
        operation_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        operation_layout = QHBoxLayout(operation_box)
        
        self.view_keys_btn = QPushButton("VIEW KEYS")
        self.view_keys_btn.setCheckable(True)
        self.view_keys_btn.setChecked(True)
        self.view_keys_btn.clicked.connect(lambda: self.keys_stack.setCurrentIndex(0))
        
        self.generate_key_btn = QPushButton("GENERATE KEY")
        self.generate_key_btn.setCheckable(True)
        self.generate_key_btn.clicked.connect(lambda: self.keys_stack.setCurrentIndex(1))
        
        self.import_key_btn = QPushButton("IMPORT KEY")
        self.import_key_btn.setCheckable(True)
        self.import_key_btn.clicked.connect(lambda: self.keys_stack.setCurrentIndex(2))
        
        self.export_key_btn = QPushButton("EXPORT KEY")
        self.export_key_btn.setCheckable(True)
        self.export_key_btn.clicked.connect(lambda: self.keys_stack.setCurrentIndex(3))
        
        # Style buttons as toggle group
        for btn in [self.view_keys_btn, self.generate_key_btn, self.import_key_btn, self.export_key_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #222222;
                    color: #aaaaaa;
                    border: 1px solid #444444;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:checked {
                    background-color: #00aaff;
                    color: #ffffff;
                }
                QPushButton:hover:!checked {
                    background-color: #333333;
                }
            """)
        
        operation_layout.addWidget(self.view_keys_btn)
        operation_layout.addWidget(self.generate_key_btn)
        operation_layout.addWidget(self.import_key_btn)
        operation_layout.addWidget(self.export_key_btn)
        
        layout.addWidget(operation_box)
        
        # Create view keys page
        view_page = QWidget()
        view_layout = QVBoxLayout(view_page)
        
        # Key list
        view_layout.addWidget(QLabel("AVAILABLE KEYS:"))
        self.keys_list = QListWidget()
        self.keys_list.setStyleSheet("""
            QListWidget {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QListWidget::item:selected {
                background-color: #00aaff;
                color: #ffffff;
            }
        """)
        view_layout.addWidget(self.keys_list)
        
        details_box = QGroupBox("KEY DETAILS")
        details_box.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #444444;
                margin-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        details_layout = QVBoxLayout(details_box)
        
        self.key_name_label = QLabel("NAME: ")
        self.key_type_label = QLabel("TYPE: ")
        self.key_created_label = QLabel("CREATED: ")
        self.key_description_label = QLabel("DESCRIPTION: ")
        self.key_status_label = QLabel("STATUS: ")
        self.key_fingerprint_label = QLabel("FINGERPRINT: ")
        
        for label in [self.key_name_label, self.key_type_label, self.key_created_label, 
                     self.key_description_label, self.key_status_label, self.key_fingerprint_label]:
            label.setStyleSheet("color: #ffffff;")
            details_layout.addWidget(label)
        
        self.delete_key_button = QPushButton("DELETE KEY")
        self.delete_key_button.setStyleSheet("""
            QPushButton {
                background-color: #770000;
                color: #ffffff;
                border: none;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #880000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        """)
        self.delete_key_button.clicked.connect(self.delete_selected_key)
        details_layout.addWidget(self.delete_key_button)
        
        view_layout.addWidget(details_box)
        
        generate_page = QWidget()
        generate_layout = QVBoxLayout(generate_page)
        
        form_layout = QGridLayout()
        
        form_layout.addWidget(QLabel("KEY NAME:"), 0, 0)
        self.new_key_name = QLineEdit()
        self.new_key_name.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        form_layout.addWidget(self.new_key_name, 0, 1)
        
        form_layout.addWidget(QLabel("DESCRIPTION:"), 1, 0)
        self.new_key_description = QLineEdit()
        self.new_key_description.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        form_layout.addWidget(self.new_key_description, 1, 1)
        
        form_layout.addWidget(QLabel("KEY TYPE:"), 2, 0)
        self.new_key_type = QComboBox()
        self.new_key_type.addItems(["RSA", "Curve25519"])
        self.new_key_type.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                selection-background-color: #00aaff;
            }
        """)
        form_layout.addWidget(self.new_key_type, 2, 1)
        
        form_layout.addWidget(QLabel("PASSWORD:"), 3, 0)
        self.new_key_password = QLineEdit()
        self.new_key_password.setEchoMode(QLineEdit.Password)
        self.new_key_password.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        form_layout.addWidget(self.new_key_password, 3, 1)
        
        form_layout.addWidget(QLabel("CONFIRM PASSWORD:"), 4, 0)
        self.new_key_confirm_password = QLineEdit()
        self.new_key_confirm_password.setEchoMode(QLineEdit.Password)
        self.new_key_confirm_password.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        form_layout.addWidget(self.new_key_confirm_password, 4, 1)
        
        generate_layout.addLayout(form_layout)
        
        self.generate_key_button = QPushButton("GENERATE KEY PAIR")
        self.generate_key_button.setStyleSheet("""
            QPushButton {
                background-color: #007700;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008800;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
        """)
        self.generate_key_button.clicked.connect(self.generate_new_keypair)
        generate_layout.addWidget(self.generate_key_button)
        
        self.generate_progress = ProgressMeter()
        self.generate_progress.set_color(QColor(0, 200, 0))
        generate_layout.addWidget(self.generate_progress)
        
        self.generate_status = QLabel("")
        self.generate_status.setStyleSheet("color: #00ff00;")
        generate_layout.addWidget(self.generate_status)
        
        generate_layout.addStretch()
        
        import_page = QWidget()
        import_layout = QVBoxLayout(import_page)
        
        import_form = QGridLayout()
        
        import_form.addWidget(QLabel("KEY NAME:"), 0, 0)
        self.import_key_name = QLineEdit()
        self.import_key_name.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        import_form.addWidget(self.import_key_name, 0, 1)
        
        import_form.addWidget(QLabel("DESCRIPTION:"), 1, 0)
        self.import_key_description = QLineEdit()
        self.import_key_description.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        import_form.addWidget(self.import_key_description, 1, 1)
        
        import_form.addWidget(QLabel("KEY FILE:"), 2, 0)
        
        key_file_layout = QHBoxLayout()
        self.import_key_path = QLineEdit()
        self.import_key_path.setReadOnly(True)
        self.import_key_path.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        
        self.browse_key_button = QPushButton("BROWSE")
        self.browse_key_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.browse_key_button.clicked.connect(self.browse_import_key)
        
        key_file_layout.addWidget(self.import_key_path)
        key_file_layout.addWidget(self.browse_key_button)
        
        import_form.addLayout(key_file_layout, 2, 1)
        
        import_form.addWidget(QLabel("PASSWORD:"), 3, 0)
        self.import_key_password = QLineEdit()
        self.import_key_password.setEchoMode(QLineEdit.Password)
        self.import_key_password.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        import_form.addWidget(self.import_key_password, 3, 1)
        
        import_form.addWidget(QLabel("CONFIRM PASSWORD:"), 4, 0)
        self.import_key_confirm_password = QLineEdit()
        self.import_key_confirm_password.setEchoMode(QLineEdit.Password)
        self.import_key_confirm_password.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        import_form.addWidget(self.import_key_confirm_password, 4, 1)
        
        import_layout.addLayout(import_form)
        
        self.import_key_button = QPushButton("IMPORT KEY")
        self.import_key_button.setStyleSheet("""
            QPushButton {
                background-color: #007700;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008800;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
        """)
        self.import_key_button.clicked.connect(self.import_key)
        import_layout.addWidget(self.import_key_button)
        
        self.import_status = QLabel("")
        self.import_status.setStyleSheet("color: #00ff00;")
        import_layout.addWidget(self.import_status)
        
        import_layout.addStretch()
        
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        
        export_layout.addWidget(QLabel("SELECT KEY TO EXPORT:"))
        self.export_key_combo = QComboBox()
        self.export_key_combo.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                selection-background-color: #00aaff;
            }
        """)
        export_layout.addWidget(self.export_key_combo)
        
        export_layout.addWidget(QLabel("KEY TYPE:"))
        self.export_key_type = QComboBox()
        self.export_key_type.addItems(["Public Key", "Private Key"])
        self.export_key_type.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                min-height: 25px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                selection-background-color: #00aaff;
            }
        """)
        export_layout.addWidget(self.export_key_type)
        
        export_layout.addWidget(QLabel("EXPORT LOCATION:"))
        
        export_path_layout = QHBoxLayout()
        self.export_path = QLineEdit()
        self.export_path.setReadOnly(True)
        self.export_path.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        
        self.browse_export_button = QPushButton("BROWSE")
        self.browse_export_button.setStyleSheet("""
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:pressed {
                background-color: #444444;
            }
        """)
        self.browse_export_button.clicked.connect(self.browse_export_location)
        
        export_path_layout.addWidget(self.export_path)
        export_path_layout.addWidget(self.browse_export_button)
        
        export_layout.addLayout(export_path_layout)
        
        self.export_password_widget = QWidget()
        export_password_layout = QHBoxLayout(self.export_password_widget)
        export_password_layout.setContentsMargins(0, 0, 0, 0)
        
        export_password_layout.addWidget(QLabel("PASSWORD:"))
        self.export_key_password = QLineEdit()
        self.export_key_password.setEchoMode(QLineEdit.Password)
        self.export_key_password.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #444444;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        export_password_layout.addWidget(self.export_key_password)
        
        export_layout.addWidget(self.export_password_widget)
        self.export_password_widget.setVisible(False)
       
        self.export_key_type.currentIndexChanged.connect(self.toggle_export_password)
        
        self.export_key_button = QPushButton("EXPORT KEY")
        self.export_key_button.setStyleSheet("""
            QPushButton {
                background-color: #007700;
                color: #ffffff;
                border: none;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008800;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
        """)
        self.export_key_button.clicked.connect(self.export_key)
        export_layout.addWidget(self.export_key_button)
        
        self.export_status = QLabel("")
        self.export_status.setStyleSheet("color: #00ff00;")
        export_layout.addWidget(self.export_status)
        
        export_layout.addStretch()
        
        self.keys_stack.addWidget(view_page)
        self.keys_stack.addWidget(generate_page)
        self.keys_stack.addWidget(import_page)
        self.keys_stack.addWidget(export_page)
        
        layout.addWidget(self.keys_stack)
        
        self.tabs.addTab(keys_tab, "KEYS")
    
    def create_history_tab(self):
        history_tab = QWidget()
        layout = QVBoxLayout(history_tab)
        
        layout.addWidget(QLabel("OPERATION HISTORY:"))
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("""
            QListWidget {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                font-family: 'Courier New', monospace;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QListWidget::item:selected {
                background-color: #00aaff;
                color: #ffffff;
            }
        """)
        layout.addWidget(self.history_list)
        
        self.clear_history_button = QPushButton("CLEAR HISTORY")
        self.clear_history_button.setStyleSheet("""
            QPushButton {
                background-color: #770000;
                color: #ffffff;
                border: none;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #880000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        """)
        self.clear_history_button.clicked.connect(self.clear_history)
        layout.addWidget(self.clear_history_button)
        
        self.tabs.addTab(history_tab, "HISTORY")
    
    def initialize(self):
        """Initialize the application state."""
        self.load_keys_list()
        
        self.load_history()
        
        self.keys_list.currentItemChanged.connect(self.update_key_details)
        
        self.status_bar.set_status("SYSTEM READY")
    
    def load_keys_list(self):
        """Load the list of keys."""
        self.keys_list.clear()
        self.recipient_combo.clear()
        self.private_key_combo.clear()
        self.export_key_combo.clear()
        
        keys = list_keys()
        
        for key in keys:
            name = key.get("name", "Unknown")
            key_type = key.get("type", "Unknown")
            
            status = []
            if key.get("has_public", False):
                status.append("PUBLIC")
            if key.get("has_private", False):
                if key.get("private_key_encrypted", False):
                    status.append("PRIVATE (PROTECTED)")
                else:
                    status.append("PRIVATE")
            
            item_text = f"{name} - {key_type} - {', '.join(status)}"
            self.keys_list.addItem(item_text)
            
            if key.get("has_public", False):
                self.recipient_combo.addItem(name)
                self.export_key_combo.addItem(name)
            
            if key.get("has_private", False):
                self.private_key_combo.addItem(name)
                if not key.get("has_public", False):  
                    self.export_key_combo.addItem(name)
    
    def update_key_details(self, current, previous):
        """Update the key details when a key is selected."""
        if not current:
            return
        
        item_text = current.text()
        name = item_text.split(" - ")[0]
        
        keys = list_keys()
        key = next((k for k in keys if k.get("name") == name), None)
        
        if key:
            self.key_name_label.setText(f"NAME: {key.get('name', 'Unknown')}")
            self.key_type_label.setText(f"TYPE: {key.get('type', 'Unknown')}")
            
            created = key.get("created", "")
            if created:
                try:
                    created = datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M:%S")
                    self.key_created_label.setText(f"CREATED: {created}")
                except (ValueError, TypeError):
                    self.key_created_label.setText("CREATED: Unknown")
            else:
                self.key_created_label.setText("CREATED: Unknown")
            
            self.key_description_label.setText(f"DESCRIPTION: {key.get('description', '')}")
            
            status = []
            if key.get("has_public", False):
                status.append("Public Key Available")
            if key.get("has_private", False):
                if key.get("private_key_encrypted", False):
                    status.append("Private Key Protected")
                else:
                    status.append("Private Key Available")
            
            self.key_status_label.setText(f"STATUS: {', '.join(status)}")
            
            try:
                if key.get("has_public", False):
                    public_key_pem = load_key(key.get("name"), "public")
                    public_key = serialization.load_pem_public_key(
                        public_key_pem,
                        backend=default_backend()
                    )
                    
                    if isinstance(public_key, rsa.RSAPublicKey):
                        der_data = public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        fingerprint.update(der_data)
                        digest = fingerprint.finalize()
                        
                        formatted_fingerprint = ':'.join(f'{b:02x}' for b in digest[:8])
                        self.key_fingerprint_label.setText(f"FINGERPRINT: {formatted_fingerprint}...")
                    else:
                        self.key_fingerprint_label.setText("FINGERPRINT: Not available for this key type")
                else:
                    self.key_fingerprint_label.setText("FINGERPRINT: No public key available")
            except Exception:
                self.key_fingerprint_label.setText("FINGERPRINT: Error calculating fingerprint")
    
    def load_history(self):
        """Load the operation history."""
        self.history_list.clear()
        
        history = get_history()
        
        for entry in reversed(history):
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
            
            item_text = f"[{timestamp}] {operation} {details}"
            self.history_list.addItem(item_text)
    
    def clear_history(self):
        """Clear the operation history."""
        confirm = QMessageBox.question(
            self,
            "Confirm Clear History",
            "Are you sure you want to clear all history?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            if os.path.exists(HISTORY_FILE):
                try:
                    os.remove(HISTORY_FILE)
                    self.history_list.clear()
                    self.status_bar.set_status("HISTORY CLEARED")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to clear history: {str(e)}")
    
    def encrypt_with_password(self):
        """Encrypt text with a password."""
        plaintext = self.password_plaintext.toPlainText()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not plaintext:
            QMessageBox.warning(self, "Warning", "Please enter text to encrypt.")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password.")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Warning", "Passwords do not match.")
            return
        
        self.worker = CryptWorker("encrypt_password", {
            "plaintext": plaintext,
            "password": password
        })
        
        self.worker.progress.connect(self.password_progress.set_value)
        self.worker.finished.connect(self.handle_password_encrypt_result)
        self.worker.error.connect(self.handle_error)
        
        self.status_bar.set_status("ENCRYPTING...", "#ffaa00")
        self.worker.start()
    
    def handle_password_encrypt_result(self, result):
        """Handle the result of password encryption."""
        if result:
            self.password_result.setPlainText(result)
            self.status_bar.set_status("ENCRYPTION COMPLETE", "#00ff00")
        else:
            self.status_bar.set_status("ENCRYPTION FAILED", "#ff0000")
    
    def decrypt_with_password(self):
        """Decrypt text with a password."""
        encrypted = self.password_encrypted.toPlainText()
        password = self.decrypt_password_input.text()
        
        if not encrypted:
            QMessageBox.warning(self, "Warning", "Please enter encrypted text to decrypt.")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password.")
            return
        
        self.worker = CryptWorker("decrypt_password", {
            "encrypted": encrypted,
            "password": password
        })
        
        self.worker.progress.connect(self.decrypt_password_progress.set_value)
        self.worker.finished.connect(self.handle_password_decrypt_result)
        self.worker.error.connect(self.handle_error)
        
        self.status_bar.set_status("DECRYPTING...", "#ffaa00")
        self.worker.start()
    
    def handle_password_decrypt_result(self, result):
        """Handle the result of password decryption."""
        if result:
            self.password_decrypted.setPlainText(result)
            self.status_bar.set_status("DECRYPTION COMPLETE", "#00ff00")
        else:
            self.status_bar.set_status("DECRYPTION FAILED", "#ff0000")
    
    def encrypt_with_public_key(self):
        """Encrypt text with a public key."""
        plaintext = self.key_plaintext.toPlainText()
        key_name = self.recipient_combo.currentText()
        
        if not plaintext:
            QMessageBox.warning(self, "Warning", "Please enter text to encrypt.")
            return
        
        if not key_name:
            QMessageBox.warning(self, "Warning", "Please select a recipient (public key).")
            return
        
        self.worker = CryptWorker("encrypt_public_key", {
            "plaintext": plaintext,
            "key_name": key_name
        })
        
        self.worker.progress.connect(self.key_progress.set_value)
        self.worker.finished.connect(self.handle_key_encrypt_result)
        self.worker.error.connect(self.handle_error)
        
        self.status_bar.set_status("ENCRYPTING...", "#ffaa00")
        self.worker.start()
    
    def handle_key_encrypt_result(self, result):
        """Handle the result of public key encryption."""
        if result:
            self.key_result.setPlainText(result)
            self.status_bar.set_status("ENCRYPTION COMPLETE", "#00ff00")
        else:
            self.status_bar.set_status("ENCRYPTION FAILED", "#ff0000")
    
    def decrypt_with_private_key(self):
        """Decrypt text with a private key."""
        encrypted = self.key_encrypted.toPlainText()
        key_name = self.private_key_combo.currentText()
        
        if not encrypted:
            QMessageBox.warning(self, "Warning", "Please enter encrypted text to decrypt.")
            return
        
        if not key_name:
            QMessageBox.warning(self, "Warning", "Please select a private key.")
            return
        
        keys = list_keys()
        key = next((k for k in keys if k.get("name") == key_name), None)
        
        if key and key.get("private_key_encrypted", False):
            dialog = PasswordDialog(key_name, self)
            if dialog.exec_() == QDialog.Accepted:
                password = dialog.password
            else:
                return
        else:
            password = None
        
        self.worker = CryptWorker("decrypt_private_key", {
            "encrypted": encrypted,
            "key_name": key_name,
            "password": password
        })
        
        self.worker.progress.connect(self.decrypt_key_progress.set_value)
        self.worker.finished.connect(self.handle_key_decrypt_result)
        self.worker.error.connect(self.handle_error)
        
        self.status_bar.set_status("DECRYPTING...", "#ffaa00")
        self.worker.start()
    
    def handle_key_decrypt_result(self, result):
        """Handle the result of private key decryption."""
        if result:
            self.key_decrypted.setPlainText(result)
            self.status_bar.set_status("DECRYPTION COMPLETE", "#00ff00")
        else:
            self.status_bar.set_status("DECRYPTION FAILED", "#ff0000")
    
    def generate_new_keypair(self):
        """Generate a new key pair."""
        name = self.new_key_name.text()
        description = self.new_key_description.text()
        key_type = self.new_key_type.currentText().lower()
        password = self.new_key_password.text()
        confirm_password = self.new_key_confirm_password.text()
        
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a name for the key pair.")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password to protect the private key.")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Warning", "Passwords do not match.")
            return
        
        keys = list_keys()
        if any(k.get("name") == name for k in keys):
            confirm = QMessageBox.question(
                self,
                "Confirm Overwrite",
                f"A key with the name '{name}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if confirm == QMessageBox.No:
                return
        
        self.worker = CryptWorker("generate_keypair", {
            "name": name,
            "description": description,
            "key_type": key_type,
            "password": password
        })
        
        self.worker = CryptWorker("generate_keypair", {
            "name": name,
            "description": description,
            "key_type": key_type,
            "password": password
        })
        
        self.worker.progress.connect(self.generate_progress.set_value)
        self.worker.finished.connect(self.handle_generate_keypair_result)
        self.worker.error.connect(self.handle_error)
        
        self.status_bar.set_status("GENERATING KEY PAIR...", "#ffaa00")
        self.worker.start()
    
    def handle_generate_keypair_result(self, result):
        """Handle the result of key pair generation."""
        if result and result.get("success"):
            self.generate_status.setText(f"Key pair '{result.get('name')}' generated successfully.")
            self.status_bar.set_status("KEY PAIR GENERATED", "#00ff00")
            self.load_keys_list()
        else:
            error = result.get("error", "Unknown error")
            self.generate_status.setText(f"Key pair generation failed: {error}")
            self.generate_status.setStyleSheet("color: #ff0000;")
            self.status_bar.set_status("KEY PAIR GENERATION FAILED", "#ff0000")
    
    def browse_import_key(self):
        """Browse for a key file to import."""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Select Key File",
            "",
            "Key Files (*.pem *.key *.pub);;All Files (*)"
        )
        
        if file_path:
            self.import_key_path.setText(file_path)
    
    def import_key(self):
        """Import a key from a file."""
        name = self.import_key_name.text()
        description = self.import_key_description.text()
        file_path = self.import_key_path.text()
        password = self.import_key_password.text()
        confirm_password = self.import_key_confirm_password.text()
        
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a name for the key.")
            return
        
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a key file to import.")
            return
        
        keys = list_keys()
        if any(k.get("name") == name for k in keys):
            confirm = QMessageBox.question(
                self,
                "Confirm Overwrite",
                f"A key with the name '{name}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if confirm == QMessageBox.No:
                return
        
        try:
            with open(file_path, 'rb') as f:
                key_data = f.read()
            
            try:
                public_key = serialization.load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                key_type = "public"
                has_public = True
                has_private = False
                private_key_encrypted = False
            except ValueError:
                try:
                    private_key = serialization.load_pem_private_key(
                        key_data,
                        password=None if not password else password.encode(),
                        backend=default_backend()
                    )
                    key_type = "private"
                    has_public = False
                    has_private = True
                    private_key_encrypted = False if not password else True
                    
                    if password:
                        if password != confirm_password:
                            QMessageBox.warning(self, "Warning", "Passwords do not match.")
                            return
                        
                        key_data = encrypt_private_key(key_data, password)
                        private_key_encrypted = True
                except ValueError as e:
                    QMessageBox.critical(self, "Error", f"Invalid key file: {str(e)}")
                    return
            
            try:
                os.makedirs(KEY_DIRECTORY, exist_ok=True)
                
                metadata = {
                    "name": name,
                    "description": description,
                    "created": datetime.now().isoformat(),
                    "type": "RSA" if b"RSA" in key_data else "Ed25519",
                    "has_private": has_private,
                    "has_public": has_public,
                    "private_key_encrypted": private_key_encrypted
                }
                
                metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                key_path = os.path.join(KEY_DIRECTORY, f"{name}.{key_type}.pem")
                with open(key_path, 'wb') as f:
                    f.write(key_data)
                
                self.import_status.setText("Key imported successfully.")
                self.import_status.setStyleSheet("color: #00ff00;")
                self.status_bar.set_status("KEY IMPORTED", "#00ff00")
                self.load_keys_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save key: {str(e)}")
                self.import_status.setText(f"Failed to import key: {str(e)}")
                self.import_status.setStyleSheet("color: #ff0000;")
                self.status_bar.set_status("KEY IMPORT FAILED", "#ff0000")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Key file not found.")
            self.import_status.setText("Key file not found.")
            self.import_status.setStyleSheet("color: #ff0000;")
            self.status_bar.set_status("KEY IMPORT FAILED", "#ff0000")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read key file: {str(e)}")
            self.import_status.setText(f"Failed to read key file: {str(e)}")
            self.import_status.setStyleSheet("color: #ff0000;")
            self.status_bar.set_status("KEY IMPORT FAILED", "#ff0000")
    
    def browse_export_location(self):
        """Browse for an export location."""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self,
            "Select Export Location",
            "",
            "Key Files (*.pem *.key *.pub);;All Files (*)"
        )
        
        if file_path:
            self.export_path.setText(file_path)
    
    def toggle_export_password(self, index):
        """Toggle the password field visibility based on key type."""
        if self.export_key_type.currentText() == "Private Key":
            self.export_password_widget.setVisible(True)
        else:
            self.export_password_widget.setVisible(False)
    
    def export_key(self):
        """Export a key to a file."""
        name = self.export_key_combo.currentText()
        key_type = self.export_key_type.currentText().lower().replace(" key", "")
        export_path = self.export_path.text()
        password = self.export_key_password.text()
        
        if not name:
            QMessageBox.warning(self, "Warning", "Please select a key to export.")
            return
        
        if not export_path:
            QMessageBox.warning(self, "Warning", "Please select an export location.")
            return
        
        try:
            try:
                key_data = load_key(name, key_type, password)
            except ValueError as e:
                QMessageBox.critical(self, "Error", str(e))
                self.export_status.setText(str(e))
                self.export_status.setStyleSheet("color: #ff0000;")
                self.status_bar.set_status("KEY EXPORT FAILED", "#ff0000")
                return
            
            try:
                with open(export_path, 'wb') as f:
                    f.write(key_data)
                
                self.export_status.setText("Key exported successfully.")
                self.export_status.setStyleSheet("color: #00ff00;")
                self.status_bar.set_status("KEY EXPORTED", "#00ff00")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to write key to file: {str(e)}")
                self.export_status.setText(f"Failed to write key to file: {str(e)}")
                self.export_status.setStyleSheet("color: #ff0000;")
                self.status_bar.set_status("KEY EXPORT FAILED", "#ff0000")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Key not found.")
            self.export_status.setText("Key not found.")
            self.export_status.setStyleSheet("color: #ff0000;")
            self.status_bar.set_status("KEY EXPORT FAILED", "#ff0000")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load key: {str(e)}")
            self.export_status.setText(f"Failed to load key: {str(e)}")
            self.export_status.setStyleSheet("color: #ff0000;")
            self.status_bar.set_status("KEY EXPORT FAILED", "#ff0000")
    
    def delete_selected_key(self):
        """Delete the selected key."""
        selected_item = self.keys_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Warning", "Please select a key to delete.")
            return
        
        item_text = selected_item.text()
        name = item_text.split(" - ")[0]
        
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete the key '{name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            try:
                metadata_path = os.path.join(KEY_DIRECTORY, f"{name}.meta.json")
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
                
                public_key_path = os.path.join(KEY_DIRECTORY, f"{name}.public.pem")
                if os.path.exists(public_key_path):
                    os.remove(public_key_path)
                
                private_key_path = os.path.join(KEY_DIRECTORY, f"{name}.private.pem")
                if os.path.exists(private_key_path):
                    os.remove(private_key_path)
                
                self.status_bar.set_status("KEY DELETED", "#00ff00")
                self.load_keys_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete key: {str(e)}")
                self.status_bar.set_status("KEY DELETION FAILED", "#ff0000")
    
    def handle_error(self, message):
        """Handle an error message."""
        QMessageBox.critical(self, "Error", message)
        self.status_bar.set_status("ERROR: " + message, "#ff0000")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    
    app_icon = QIcon("assets/c-crypt-pro-icon.png")
    app.setWindowIcon(app_icon)
    
    gui = CCryptProGUI()
    gui.show()
    
    sys.exit(app.exec_())

