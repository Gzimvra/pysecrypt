import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


SALT_SIZE = 16
IV_SIZE = 16
BLOCK_SIZE = 128
KEY_SIZE = 32

class AES_Encryption:
    """
    A class to perform AES encryption and decryption on files and folders.

    This class provides methods for encrypting and decrypting data using the AES algorithm in various modes: CBC, CTR, and GCM. It supports encryption and decryption of individual files as well as entire folders, recursively handling all files within a folder. It can derive AES keys from a password or use a pre-derived key, ensuring secure encryption practices. The class also supports saving the encrypted or decrypted data while maintaining the folder structure and adding appropriate file extensions (e.g., '.enc' for encrypted files).

    ### Supported Modes:
        - CBC (Cipher Block Chaining): A block cipher mode that requires padding for plaintext.
        - CTR (Counter): A stream cipher mode that allows plaintext encryption without padding.
        - GCM (Galois/Counter Mode): A mode that provides both encryption and authentication for integrity verification.

    ### Methods:
        encrypt(input_path: str, output_path: str) -> None:
            Encrypts a file or folder using AES encryption.
        decrypt(input_path: str, output_path: str) -> None:
            Decrypts a file or folder using AES decryption.
        encrypt_file(input_file: str, output_file: str) -> None:
            Encrypts a single file.
        decrypt_file(input_file: str, output_file: str) -> None:
            Decrypts a single file.
        encrypt_folder(input_folder: str, output_folder: str) -> None:
            Encrypts all files within a folder and its subfolders.
        decrypt_folder(input_folder: str, output_folder: str) -> None:
            Decrypts all files within a folder and its subfolders.
    
    ### Attributes:
        key (bytes): The AES key used for encryption and decryption.
        salt (bytes): A random salt used for key derivation when a password is provided.
        mode (str): The AES mode (CBC, CTR, GCM) used for encryption and decryption.
    """

    def __init__(self, password_or_key: str | bytes, mode: str = 'CBC') -> None:
        """
        Initializes the AES_Encryption class for AES encryption and decryption using either a password or a pre-derived key.

        If a password (string) is provided, it is converted to bytes and used to derive a 32-byte AES key using PBKDF2HMAC with SHA-256 and a random salt. If a pre-derived key (bytes) is provided, it is used directly without derivation.

        The constructor also sets the encryption mode, which can be:
        - CBC (Cipher Block Chaining): Requires padding for plaintext.
        - CTR (Counter): A stream cipher mode that does not require padding.
        - GCM (Galois/Counter Mode): Provides both encryption and authentication (integrity verification).

        Parameters:
            password_or_key (str | bytes): The password (string) or pre-derived key (bytes) for AES encryption.
            mode (str): The AES encryption mode ('CBC', 'CTR', or 'GCM', default is 'CBC').

        Raises:
            ValueError: If `password_or_key` is neither a string nor bytes.
        """
        try:
            self.backend = default_backend()
            self.mode = mode.upper()  # Store the mode (CBC, CTR, or GCM)

            if isinstance(password_or_key, str):
                # Input is a password (str), so derive the key
                self.password = password_or_key.encode()  # Convert password to bytes
                self.salt = os.urandom(SALT_SIZE)  # Generate a random salt
                self.key = self._derive_key()
                logging.info("Key derived successfully from the provided password.")
            elif isinstance(password_or_key, bytes):
                # Input is a pre-derived key (bytes), so use it directly
                self.password = None  # No password in this case
                self.key = password_or_key
                self.salt = None  # No salt needed when using a pre-derived key
                logging.info("Using provided key directly.")
            else:
                logging.error("Invalid type for password_or_key. Must be str or bytes.")
                raise ValueError("password_or_key must be a string (password) or bytes (key).")
        except Exception as e:
            logging.error(f"Unexpected error during initialization: {e}")
            raise


    def _derive_key(self) -> bytes:
        """
        Derives a 32-byte AES encryption key from the password and salt using the PBKDF2HMAC key derivation function.

        This method uses the PBKDF2HMAC algorithm with SHA-256 to securely derive an AES encryption key from the provided password and salt. It strengthens the process by using a high iteration count (100,000) to make brute-force attacks more difficult. The derived key is essential for the AES encryption and decryption processes when a password is used as input.

        The key derivation process ensures that even if the password is weak, the key will still be strong due to the combination of the salt and the computationally expensive PBKDF2HMAC algorithm.

        Returns:
            bytes: A securely derived 32-byte AES encryption key.

        Raises:
            Exception: If an error occurs during the key derivation process, such as an invalid salt or algorithm issue.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=KEY_SIZE,
                salt=self.salt,
                iterations=100_000,
                backend=self.backend
            )
            return kdf.derive(self.password)
        
        except Exception as e:
            logging.error(f"Error deriving key: {e}")
            raise

    # ------------------------------------- ENCRYPT/DECRYPT FILES -------------------------------------

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Encrypts a file using AES encryption in the specified mode (CBC, CTR, or GCM).

        This method encrypts the content of the provided input file using AES encryption in one of the supported modes: CBC (Cipher Block Chaining), CTR (Counter), or GCM (Galois/Counter Mode). The input file is read as binary data, and the appropriate encryption steps are applied based on the selected mode:
        
        - CBC: The plaintext is padded to a multiple of the block size, then encrypted using a randomly generated initialization vector (IV).
        - CTR: The plaintext is encrypted without padding using a randomly generated nonce as the IV.
        - GCM: The plaintext is encrypted with automatic padding, and an authentication tag is generated to ensure both encryption and integrity.

        The method writes the encrypted content, along with the salt and IV (and authentication tag for GCM), to the output file.

        Parameters:
            input_file (str): The path to the file to be encrypted.
            output_file (str): The path where the encrypted file will be saved.

        Raises:
            FileNotFoundError: If the input file does not exist.
            PermissionError: If there are permission issues when reading or writing the file.
            ValueError: If the encryption mode is unsupported.
            Exception: If an unexpected error occurs during the encryption process.
        """
        try:
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"Input file '{input_file}' does not exist.")
            
            if self.mode.upper() == 'CBC':
                iv = os.urandom(IV_SIZE)  # Random Initialization Vector
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
                encryptor = cipher.encryptor()

                with open(input_file, 'rb') as f:
                    plaintext = f.read()

                # Pad the plaintext to be a multiple of the block size (16 bytes)
                padder = padding.PKCS7(BLOCK_SIZE).padder()
                padded_plaintext = padder.update(plaintext) + padder.finalize()

                # Encrypt the padded plaintext
                ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

                # Save the salt, IV, and ciphertext to the output file
                with open(output_file, 'wb') as f:
                    f.write(self.salt + iv + ciphertext)

            elif self.mode.upper() == 'CTR':
                iv = os.urandom(IV_SIZE)  # Random Initialization Vector (Nonce)
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
                encryptor = cipher.encryptor()

                with open(input_file, 'rb') as f:
                    plaintext = f.read()

                # Encrypt the plaintext (CTR mode does not require padding)
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

                # Save the salt, IV, and ciphertext to the output file
                with open(output_file, 'wb') as f:
                    f.write(self.salt + iv + ciphertext)

            elif self.mode == 'GCM':
                iv = os.urandom(IV_SIZE)  # Random Initialization Vector (Nonce)
                cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=self.backend)
                encryptor = cipher.encryptor()

                with open(input_file, 'rb') as f:
                    plaintext = f.read()

                # Encrypt the plaintext (GCM mode automatically handles padding and adds authentication tag)
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

                # Get the authentication tag
                tag = encryptor.tag

                # Save the salt, IV, tag, and ciphertext to the output file
                with open(output_file, 'wb') as f:
                    f.write(self.salt + iv + tag + ciphertext)

            else:
                logging.error(f"Unsupported mode: {self.mode}")
                raise ValueError(f"Unsupported mode: {self.mode}")
            
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
        Decrypts an encrypted file using AES decryption in the specified mode (CBC, CTR, or GCM).

        This method decrypts an encrypted file by applying the AES decryption algorithm in one of the supported modes: CBC (Cipher Block Chaining), CTR (Counter), or GCM (Galois/Counter Mode). The encrypted file is read as binary, and the necessary steps for decryption are performed based on the mode:
        
        - CBC: The ciphertext is decrypted using a randomly generated initialization vector (IV), followed by padding removal to restore the original plaintext.
        - CTR: The ciphertext is decrypted using a nonce as the IV without the need for padding.
        - GCM: The ciphertext is decrypted, and the integrity of the data is verified using the authentication tag, which was generated during encryption.

        The decrypted content is written to the specified output file, restoring the original file.

        Parameters:
            input_file (str): The path to the encrypted file that needs to be decrypted.
            output_file (str): The path where the decrypted file will be saved.

        Raises:
            FileNotFoundError: If the input file does not exist.
            PermissionError: If there are permission issues when reading or writing the file.
            ValueError: If the encryption mode is unsupported.
            Exception: If an unexpected error occurs during the decryption process.
        """
        try:
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"Input file '{input_file}' does not exist.")

            with open(input_file, 'rb') as f:
                data = f.read()

            # Extract the salt, IV, tag (if GCM), and ciphertext
            salt = data[:SALT_SIZE]
            iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
            
            if self.mode == 'GCM':
                tag = data[SALT_SIZE + IV_SIZE:SALT_SIZE + IV_SIZE + 16]  # GCM tag is 16 bytes
                ciphertext = data[SALT_SIZE + IV_SIZE + 16:]
            else:
                tag = None
                ciphertext = data[SALT_SIZE + IV_SIZE:]

            # Derive the key again using the extracted salt if password was used
            if self.password:
                self.salt = salt
                self.key = self._derive_key()

            if self.mode == 'CBC':
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
                decryptor = cipher.decryptor()

                # Decrypt the ciphertext
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                # Remove padding from the plaintext
                unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            elif self.mode == 'CTR':
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
                decryptor = cipher.decryptor()

                # Decrypt the ciphertext (CTR mode does not require unpadding)
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            elif self.mode == 'GCM':
                cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=self.backend)
                decryptor = cipher.decryptor()

                # Decrypt the ciphertext (GCM mode automatically handles authentication)
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            else:
                logging.error(f"Unsupported mode: {self.mode}")
                raise ValueError(f"Unsupported mode: {self.mode}")

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
        Encrypts all files within a folder and its subfolders using AES encryption.

        This method recursively traverses a folder and encrypts all files inside it using the AES encryption algorithm in the specified mode (CBC, CTR, or GCM). Each file is processed individually, and the encrypted version of each file is saved in the specified output folder, preserving the original folder structure. The encrypted files will have the `.enc` extension appended to their original names.

        Parameters:
            input_folder (str): The path to the folder containing the files to be encrypted.
            output_folder (str): The path to the folder where the encrypted files will be saved.

        Raises:
            FileNotFoundError: If the input folder does not exist.
            PermissionError: If there are permission issues during folder traversal or file encryption.
            Exception: If an unexpected error occurs during the folder encryption process.
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
        Decrypts all files within a folder and its subfolders using AES decryption.

        This method recursively traverses a folder and decrypts all files with the `.enc` extension using the AES decryption algorithm in the specified mode (CBC, CTR, or GCM). Each file is processed individually, and the decrypted version of each file is saved in the specified output folder, preserving the original folder structure. The `.enc` extension is removed from the filenames in the output folder.

        Parameters:
            input_folder (str): The path to the folder containing the encrypted files.
            output_folder (str): The path to the folder where the decrypted files will be saved.

        Raises:
            FileNotFoundError: If the input folder does not exist.
            PermissionError: If there are permission issues during folder traversal or file decryption.
            Exception: If an unexpected error occurs during the folder decryption process.
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

    def encrypt(self, input_path: str, output_path: str) -> bytes:
        """
        Encrypts a file or folder using AES encryption in the specified mode (CBC, CTR, or GCM).

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
        logging.info(f"Encrypting using AES-{self.mode}...")

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

            return self.key

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
        Decrypts a file or folder using AES decryption in the specified mode (CBC, CTR, or GCM).

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
        logging.info(f"Decrypting using AES-{self.mode}...")

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

