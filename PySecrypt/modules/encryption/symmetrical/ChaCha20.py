import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


SALT_SIZE = 16
NONCE_SIZE = 12  # Required size for ChaCha20Poly1305 nonce
KEY_SIZE = 32  # 256 bits

class ChaCha20_Encryption:
    """
    A utility class for file and folder encryption and decryption using the ChaCha20-Poly1305 encryption algorithm.

    The `ChaCha20_Encryption` class provides methods to securely encrypt and decrypt files and folders. It uses the 
    ChaCha20-Poly1305 cipher, which offers both encryption and integrity verification, ensuring that the encrypted data 
    is not only secure but also resistant to tampering.

    ### The class supports:
    - File-level encryption and decryption.
    - Folder-level encryption and decryption, preserving directory structures.
    - Key derivation using a password and salt via the PBKDF2HMAC function.

    ### Features:
    - Encryption: Encrypts files or folders with high security and appends a `.enc` extension to encrypted files.
    - Decryption: Decrypts previously encrypted files or folders and restores their original content and structure.
    - Progress Tracking: Displays progress bars for folder encryption and decryption to track operation progress.
    - Error Handling: Provides detailed logging and exception handling for common issues such as file not found, 
      permission errors, and invalid data.

    ### Parameters:
        password (str): A password used for key derivation. The password is transformed into a secure encryption key 
        using a salt and PBKDF2HMAC.

    ### Methods:
        - `encrypt_file(input_file, output_file)`: Encrypts a single file.
        - `decrypt_file(input_file, output_file)`: Decrypts a single file.
        - `encrypt_folder(input_folder, output_folder)`: Encrypts all files within a folder.
        - `decrypt_folder(input_folder, output_folder)`: Decrypts all files within a folder.
        - `_derive_key(salt)`: Derives a secure encryption key from the password and salt.
    """

    def __init__(self, password: str) -> None:
        """
        Initializes the ChaCha20_Encryption class for ChaCha20-Poly1305 encryption and decryption using a password.

        This constructor encodes the provided password into bytes for subsequent use in cryptographic operations. 
        The password will be used to derive a secure encryption key through a key derivation function

        Parameters:
            password (str): The plaintext password used for deriving an encryption key.

        Attributes:
            password (bytes): The encoded password, stored as bytes.
        """
        self.password = password.encode()


    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derives a 32-byte encryption key from the password and salt using the PBKDF2HMAC key derivation function.

        This method utilizes the PBKDF2HMAC algorithm with SHA-256 to securely derive a key for ChaCha20-Poly1305 encryption. 
        The process incorporates a high iteration count (100,000) to enhance resistance against brute-force attacks.

        The key derivation process ensures that even if the password is weak, the key will still be strong due to the combination of the salt and the computationally expensive PBKDF2HMAC algorithm.

        Parameters:
            salt (bytes): A cryptographically secure random value used to enhance key derivation security. 
                          The same salt must be used during encryption and decryption for successful operations.

        Returns:
            bytes: A securely derived 256-bit (32-byte) encryption key.

        Raises:
            Exception: If an error occurs during the key derivation process, such as an invalid salt or algorithm issue.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=KEY_SIZE,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            return kdf.derive(self.password)
        
        except Exception as e:
            logging.error(f"Error deriving key: {e}")
            raise

    # ------------------------------------- ENCRYPT/DECRYPT FILES -------------------------------------

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Encrypts a single file using ChaCha20-Poly1305 encryption.

        This method securely encrypts the contents of a file using the ChaCha20-Poly1305 encryption algorithm. It generates a 
        random salt and nonce for each encryption process to ensure the security and uniqueness of the ciphertext. The derived 
        key is used with the ChaCha20-Poly1305 cipher to encrypt the file's contents, and the resulting salt, nonce, and 
        ciphertext are saved to the specified output file.

        Parameters:
            input_file (str): The path to the file to be encrypted.
            output_file (str): The path where the encrypted file will be saved.

        Process:
            1. Verifies the existence of the input file.
            2. Generates a random salt and nonce.
            3. Derives a 256-bit encryption key using the provided password and salt.
            4. Encrypts the file's contents and optionally authenticates associated data.
            5. Writes the salt, nonce, and ciphertext to the output file.

        Raises:
            FileNotFoundError: If the input file does not exist.
            PermissionError: If there are insufficient permissions to read or write the files.
            ValueError: If an invalid input is provided to the cipher.
            Exception: For any unexpected errors during the encryption process.
        """
        try:
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"Input file '{input_file}' does not exist.")
            
            salt = os.urandom(SALT_SIZE)
            nonce = os.urandom(NONCE_SIZE)
            key = self._derive_key(salt)

            cipher = ChaCha20Poly1305(key)

            with open(input_file, 'rb') as f:
                plaintext = f.read()

            # Encrypt the plaintext and authenticate with additional data
            aad = b"file_metadata"  # Associated data (optional, can be empty)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)

            # Save the salt, nonce, and ciphertext to the output file
            with open(output_file, 'wb') as f:
                f.write(salt + nonce + ciphertext)
        
        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
            raise
        except PermissionError as e:
            logging.error(f"Permission error: {e}")
            raise
        except ValueError as e:
            logging.error(f"Value error: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during encryption: {e}")
            raise


    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Decrypts a single file using ChaCha20-Poly1305 encryption.

        This method securely decrypts the contents of a file that was encrypted using the ChaCha20-Poly1305 encryption algorithm. 
        It extracts the salt, nonce, and ciphertext from the encrypted file, derives the decryption key using the salt, and 
        decrypts the ciphertext. The decrypted plaintext is then saved to the specified output file.

        Parameters:
            input_file (str): The path to the encrypted file to be decrypted.
            output_file (str): The path where the decrypted file will be saved.

        Process:
            1. Verifies the existence of the input file.
            2. Extracts the salt, nonce, and ciphertext from the encrypted file.
            3. Derives the decryption key using the extracted salt and the provided password.
            4. Decrypts the ciphertext while verifying the associated authentication tag.
            5. Writes the decrypted plaintext to the output file.

        Raises:
            FileNotFoundError: If the input file does not exist.
            PermissionError: If there are insufficient permissions to read or write the files.
            ValueError: If decryption fails due to an authentication tag mismatch or data corruption.
            Exception: For any unexpected errors during the decryption process.
        """
        try:
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"Input file '{input_file}' does not exist.")
        
            with open(input_file, 'rb') as f:
                data = f.read()

            # Extract salt, nonce, and ciphertext
            salt = data[:SALT_SIZE]
            nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
            ciphertext = data[SALT_SIZE + NONCE_SIZE:]

            key = self._derive_key(salt)
            cipher = ChaCha20Poly1305(key)

            # Decrypt the ciphertext and verify authentication tag
            aad = b"file_metadata"  # Associated data (must match encryption)
            try:
                plaintext = cipher.decrypt(nonce, ciphertext, aad)
            except Exception as e:
                raise ValueError("Decryption failed: Authentication tag mismatch or data corruption.") from e

            # Save the decrypted plaintext to the output file
            with open(output_file, 'wb') as f:
                f.write(plaintext)

        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
            raise
        except PermissionError as e:
            logging.error(f"Permission error: {e}")
            raise
        except ValueError as e:
            logging.error(f"Value error: {e}")
            raise
        except Exception as e:
            logging.error(f"Error decrypting file {input_file}: {e}")
            raise

    # ------------------------------------- ENCRYPT/DECRYPT FOLDERS -------------------------------------

    def encrypt_folder(self, input_folder: str, output_folder: str) -> None:
        """
        Encrypts all files within a folder using ChaCha20-Poly1305 encryption.

        This method recursively scans the specified input folder, identifies all files, and encrypts them using the 
        `encrypt_file` method. The encrypted files are saved to the specified output folder, maintaining the original 
        folder structure relative to the input folder, with the `.enc` extension appended to each file name.

        Parameters:
            input_folder (str): The path to the folder containing the files to be encrypted.
            output_folder (str): The path to the folder where the encrypted files will be saved.

        Process:
            1. Validates the existence of the input folder.
            2. Scans the folder recursively to find all files for encryption.
            3. Encrypts each file and saves the encrypted content to the corresponding path in the output folder.
            4. Preserves the relative folder structure during the encryption process, appending `.enc` to file names.

        Raises:
            FileNotFoundError: If the input folder does not exist.
            PermissionError: If there are insufficient permissions to access or modify the files or folders.
            Exception: For any unexpected errors during the folder encryption process.
        """
        try:
            if not os.path.exists(input_folder):
                raise FileNotFoundError(f"Input folder '{input_folder}' does not exist.")
        
            files_to_encrypt = []
            for root, _, files in os.walk(input_folder):
                for file in files:
                    files_to_encrypt.append((root, file))

            for root, file in tqdm(files_to_encrypt, desc="Encrypting Files", unit="file"):
                input_file = os.path.join(root, file)
                relative_path = os.path.relpath(input_file, input_folder)
                output_file = os.path.join(output_folder, relative_path + '.enc')

                # Ensure output folder exists
                os.makedirs(os.path.dirname(output_file), exist_ok=True)

                self.encrypt_file(input_file, output_file)

        except FileNotFoundError as e:
            logging.error(f"Folder not found: {e}")
            raise
        except PermissionError as e:
            logging.error(f"Permission error: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during folder encryption: {e}")
            raise


    def decrypt_folder(self, input_folder: str, output_folder: str) -> None:
        """
        Decrypts all files within a folder that were encrypted using ChaCha20-Poly1305.

        This method iterates through all files in the specified input folder, identifies files with the `.enc` extension, 
        and decrypts them using the `decrypt_file` method. The decrypted files are saved to the specified output folder, 
        maintaining the original folder structure relative to the input folder. A progress bar is displayed to indicate 
        the decryption progress.

        Parameters:
            input_folder (str): The path to the folder containing the encrypted files.
            output_folder (str): The path to the folder where the decrypted files will be saved.

        Process:
            1. Validates the existence of the input folder.
            2. Scans the folder recursively to find all files with the `.enc` extension.
            3. Decrypts each file and saves the decrypted content to the corresponding path in the output folder.
            4. Preserves the relative folder structure during the decryption process.

        Raises:
            FileNotFoundError: If the input folder does not exist.
            PermissionError: If there are insufficient permissions to access or modify the files or folders.
            Exception: For any unexpected errors during the folder decryption process.
        """
        try:
            if not os.path.exists(input_folder):
                raise FileNotFoundError(f"Input folder '{input_folder}' does not exist.")

            files_to_decrypt = []
            for root, _, files in os.walk(input_folder):
                for file in files:
                    if file.endswith('.enc'):
                        files_to_decrypt.append((root, file))

            for root, file in tqdm(files_to_decrypt, desc="Decrypting Files", unit="file"):
                input_file = os.path.join(root, file)
                relative_path = os.path.relpath(input_file, input_folder)
                output_file = os.path.join(output_folder, relative_path[:-4])  # Remove .enc

                # Ensure output folder exists
                os.makedirs(os.path.dirname(output_file), exist_ok=True)

                self.decrypt_file(input_file, output_file)

        except FileNotFoundError as e:
            logging.error(f"Folder not found: {e}")
            raise
        except PermissionError as e:
            logging.error(f"Permission error: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during folder decryption: {e}")
            raise

    # ---------------------------- MAIN ENCRYPTION AND DECRYPTION FUNCTIONS ----------------------------

    def encrypt(self, input_path: str, output_path: str) -> None:
        """
        Encrypts a file or folder using ChaCha20-Poly1305 encryption model.

        This method determines whether the input path refers to a file or a folder and processes it accordingly. If the input is a file, the `encrypt_file` method is called to encrypt it. If the input is a folder, the `encrypt_folder` method is called to encrypt all files within the folder. The encrypted output is saved to the specified output path, maintaining the appropriate file extensions or folder structure.

        Parameters:
            input_path (str): The path to the file or folder to be encrypted.
            output_path (str): The path where the encrypted output will be saved.

        Raises:
            FileNotFoundError: If the input path does not exist.
            ValueError: If the input type is unsupported (neither a file nor a folder).
            Exception: If an unexpected error occurs during the encryption process.
        """
        logging.info("Starting encryption process...")
        logging.info(f"Encrypting using ChaCha20-Poly1305...")

        try:
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"The path '{input_path}' does not exist.")
            
            if os.path.isfile(input_path):
                # Build the correct output path for files
                output_path += '.enc' if not output_path.endswith('.enc') else ''
                self.encrypt_file(input_path, output_path)

            elif os.path.isdir(input_path):
                # Build the correct output path for directories
                output_path = output_path + "_encrypted"
                self.encrypt_folder(input_path, output_path)

            else:
                raise ValueError("Unsupported input type. Only files and directories are supported.")
            
            logging.info("Encryption successful.")
            logging.info(f"{os.path.basename(input_path)} has been encrypted and saved to:\n{output_path}\n")
        
        except FileNotFoundError as e:
            logging.error(f"Path not found: {e}")
            raise
        except ValueError as e:
            logging.error(f"Encryption failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during encryption: {e}")
            raise


    def decrypt(self, input_path: str, output_path: str) -> None:
        """
        Decrypts a file or folder using ChaCha20-Poly1305 encryption model.

        This method determines whether the input path refers to a file or a folder and processes it accordingly. If the input is a file, the `decrypt_file` method is called to decrypt it. If the input is a folder, the `decrypt_folder` method is called to decrypt all files within the folder. The decrypted output is saved to the specified output path, preserving the original file extensions or folder structure.

        Parameters:
            input_path (str): The path to the encrypted file or folder to be decrypted.
            output_path (str): The path where the decrypted output will be saved.

        Raises:
            FileNotFoundError: If the input path does not exist.
            ValueError: If the input type is unsupported (neither a file nor a folder).
            Exception: If an unexpected error occurs during the decryption process.
        """
        logging.info("Starting decryption process...")
        logging.info(f"Decrypting using ChaCha20-Poly1305...")

        try:
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"The path '{input_path}' does not exist.")

            if os.path.isfile(input_path):
                # Build the correct output path for files
                output_path = output_path[:-4] if output_path.endswith('.enc') else output_path
                self.decrypt_file(input_path, output_path)

            elif os.path.isdir(input_path):
                # Build the correct output path for directories
                if input_path.endswith("_encrypted"):
                    output_path = output_path.replace("_encrypted", "_decrypted")

                else:
                    output_path = output_path + "_decrypted"

                self.decrypt_folder(input_path, output_path)

            else:
                raise ValueError("Unsupported input type. Only files and directories are supported.")
            
            logging.info("Decryption successful.")
            logging.info(f"{os.path.basename(input_path)} has been decrypted and saved to:\n{output_path}\n")
            
        except FileNotFoundError as e:
            logging.error(f"Path not found: {e}")
            raise
        except ValueError as e:
            logging.error(f"Decryption failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during decryption: {e}")
            raise

