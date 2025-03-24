# 🛠 **C-Crypt Pro**

## 📌 **Overview**
C-Crypt Pro is a **hybrid encryption tool** that securely encrypts messages and files using a combination of **AES-256-GCM, Argon2id, and Public/Private Key Encryption** (RSA or Ed25519). It allows users to share encrypted data without exchanging passwords, improving security while maintaining ease of use.

---

## 🔐 **Encryption Workflow**

### 1️⃣ **Hybrid Encryption Approach**
C-Crypt Pro employs a **Hybrid Encryption Model** that combines:
- **Symmetric Encryption** (AES-256-GCM) for encrypting messages and files efficiently.
- **Asymmetric Encryption** (RSA or Ed25519) for securely encrypting the symmetric key.

This ensures that only the intended recipient with the correct **private key** can decrypt the data.

### 2️⃣ **Key Derivation (Argon2id)**
If using password-based encryption, C-Crypt Pro derives a **secure AES key** from the user’s password using **Argon2id**, a memory-hard key derivation function that provides strong resistance against brute-force and dictionary attacks.

### 3️⃣ **Steps for Encryption**
#### **🔹 Using Public Key (Hybrid Mode)**
1. **Generate a random AES-256 key**.
2. Encrypt the message using **AES-256-GCM** (authenticated encryption mode).
3. Encrypt the AES key using the recipient’s **Public Key (RSA/Ed25519)**.
4. Package the encrypted AES key, nonce, and ciphertext into a **Base64-encoded JSON structure**.
5. Send the encrypted message to the recipient.

#### **🔹 Using Password-Based Encryption**
1. **Derive a strong AES-256 key** from the password using **Argon2id**.
2. Encrypt the message using **AES-256-GCM**.
3. Package the encrypted data (salt, nonce, and ciphertext) into a Base64-encoded JSON format.

---

## 🔓 **Decryption Workflow**

### 1️⃣ **Decrypting with Private Key (Hybrid Mode)**
1. Extract the **encrypted AES key** from the received data.
2. Decrypt the AES key using the recipient’s **Private Key**.
3. Use the decrypted AES key to decrypt the message using **AES-256-GCM**.
4. Validate the authentication tag to ensure message integrity.

### 2️⃣ **Decrypting with Password**
1. Extract the salt and nonce from the received encrypted data.
2. Derive the AES key using **Argon2id** and the provided password.
3. Use AES-256-GCM to decrypt the ciphertext.
4. Validate the authentication tag before returning the plaintext message.

---

## 🔑 **Key Management System**

### 1️⃣ **Generating Public/Private Keys**
- Users generate an **RSA (4096-bit) or Ed25519** key pair.
- The **Public Key** can be shared with anyone.
- The **Private Key** is stored securely and optionally encrypted with a password.

### 2️⃣ **Key Storage Format**
- **Public Key:** Stored as `mykey.public.pem` (PEM format, readable & shareable)
- **Private Key:** Stored as `mykey.private.pem` (PEM format, encrypted with AES-GCM)
- **Metadata:** Stored as `mykey.meta.json`, including timestamp, encryption type, and key properties.

### 3️⃣ **Key Import/Export**
- Keys can be imported or exported using CLI commands.
- The system verifies key integrity before usage.

---

## 🗂 **File Encryption System**

### 1️⃣ **Encrypting a File**
1. Generate a **random AES-256 key**.
2. Encrypt the file content using **AES-256-GCM**.
3. Encrypt the AES key using the recipient’s **Public Key**.
4. Save the encrypted file (`.enc` extension) along with the metadata.

### 2️⃣ **Decrypting a File**
1. Extract the encrypted AES key and metadata from the `.enc` file.
2. Decrypt the AES key using the **recipient’s Private Key**.
3. Use AES-256-GCM to decrypt the file content.
4. Restore the original file with the correct encoding.

---

## 🛡 **Security Measures**

### ✅ **Protection Against Brute-Force Attacks**
- Uses **Argon2id** to slow down password-guessing attacks.
- AES-256 keys are **randomly generated** for every encryption operation.

### ✅ **Tamper Detection**
- **AES-GCM includes an authentication tag**, preventing message tampering.
- If an attacker modifies an encrypted message, **decryption will fail immediately**.

### ✅ **Metadata Minimization**
- Only **necessary metadata** is stored (timestamp, key type, encryption method).
- Does **not store plaintext message history**.

### ✅ **Secure Key Storage**
- **Private Keys are encrypted** before being stored.
- **No keys are ever stored in plaintext**.

---

## 🚀 **Performance & Scalability**

### ✅ **Fast Encryption & Decryption**
- AES-GCM ensures **fast encryption/decryption** with minimal overhead.
- Asymmetric encryption (RSA/Ed25519) is **only used for key exchange**, keeping operations lightweight.

### ✅ **Cross-Platform Compatibility**
- Works on **Windows, macOS, Linux**.
- Uses standard encryption libraries (`cryptography`, `argon2-cffi`).

---

## 🔧 **Installation**

Ensure you have Python installed, then install the dependencies:

```sh
pip install cryptography argon2-cffi pyfiglet colorama
```

Clone the repository:

```sh
git clone https://github.com/Bell-O/C-Crypt-Pro
cd C-Crypt-Pro
```

Run the program:

```sh
python c-crypt-pro.py
```

---

## 🛠 **Usage**

### 🔑 **Generate Public/Private Key Pair**

```sh
python c-crypt-pro.py --generate-key --name mykey --password mypassword
```

- Generates `mykey.public.pem` (for sharing)
- Generates `mykey.private.pem` (keep secret!)

### 🔐 **Encrypt a Message**

#### 🔹 Using Public Key

```sh
python c-crypt-pro.py --encrypt --text "Hello, world!" --key mykey.public.pem
```

#### 🔹 Using Password-Based Encryption

```sh
python c-crypt-pro.py --encrypt --text "Hello, world!" --password mypassword
```

### 🔓 **Decrypt a Message**

#### 🔹 Using Private Key

```sh
python c-crypt-pro.py --decrypt --text "ENCODED_TEXT" --key mykey.private.pem --password mypassword
```

#### 🔹 Using Password

```sh
python c-crypt-pro.py --decrypt --text "ENCODED_TEXT" --password mypassword
```

### 📁 **Encrypt & Decrypt Files**

#### 🔹 Encrypt a File

```sh
python c-crypt-pro.py --encrypt-file myfile.txt --key mykey.public.pem
```

#### 🔹 Decrypt a File

```sh
python c-crypt-pro.py --decrypt-file myfile.txt.enc --key mykey.private.pem --password mypassword
```

### 📜 **Manage Keys**

#### 🔍 List Available Keys

```sh
python c-crypt-pro.py --list-keys
```

#### ❌ Delete a Key

```sh
python c-crypt-pro.py --delete-key mykey --type both
```

---

## ⚠️ **Security Recommendations**

1. **Never share your Private Key!** 🔥
2. If you forget your Private Key password, **you cannot recover it.**
3. **Backup your keys in a secure location** (USB, Hardware Security Module, etc.)
4. **Use a clean system free from malware before decrypting sensitive files.**


---

## 📜 **License**

This project is licensed under the Bell Software License (BSL). See the LICENSE file for details.

---



🎯 **Enjoy Secure Encryption with C-Crypt Pro!** 🔐🚀

