import logging
import os

from PySecrypt.modules.encryption.asymmetrical.RSA import RSA_Encryption
from PySecrypt.modules.encryption.symmetrical.AES import AES_Encryption

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class AESRSA_Hybrid():
    """
    A class that implements hybrid encryption and decryption using AES and RSA algorithms.

    This class provides methods to encrypt and decrypt data using a combination of AES (Advanced Encryption 
    Standard) and RSA (Rivest–Shamir–Adleman) encryption techniques. AES is used for encrypting the data, while 
    RSA is used for securely encrypting the AES key. The AES key is encrypted with an RSA public key and later 
    decrypted with an RSA private key during decryption.

    The class includes methods for:
    - AES encryption and decryption of data files.
    - RSA encryption and decryption of AES keys.
    - A hybrid encryption and decryption workflow, where data is encrypted using AES and the AES key is encrypted 
      using RSA.
    
    Attributes:
        None.

    Methods:
        aes_encrypt_data(password: str, input_path: str, mode: str = 'CBC') -> str:
            Encrypts data using AES and returns the AES key in hexadecimal format.
        
        aes_decrypt_data(password: str, input_path: str, mode: str = 'CBC') -> None:
            Decrypts AES-encrypted data using the provided password and writes the decrypted data to the same file.
        
        rsa_encrypt_key(plaintext: str, output_folder: str = 'encrypted_keys') -> None:
            Encrypts the AES key using RSA and saves the encrypted key to a file in the specified folder.
        
        rsa_decrypt_key(encrypted_key_path: str, private_key_path: str) -> str:
            Decrypts the AES key using RSA and returns the decrypted key in hexadecimal format.
        
        encrypt(password: str, input_path: str, mode: str = 'CBC') -> None:
            Encrypts data using AES, derives the AES key, and encrypts the key using RSA.
        
        decrypt(encrypted_data_path: str, encrypted_key_path: str, private_key_path: str, mode: str = 'CBC') -> None:
            Decrypts data by first decrypting the AES key using RSA and then decrypting the data using AES.

    Raises:
        ValueError: If invalid data, keys, or file paths are provided, or if encryption/decryption fails.
        FileNotFoundError: If the specified file or key paths do not exist.
        PermissionError: If there are issues with file access permissions during encryption or decryption.
        Exception: If any other unexpected errors occur during the encryption or decryption processes.
    """

    # ------------------------------------- AES ENCRYPTION/DECRYPTION HANDLERS -------------------------------------

    def aes_encrypt_data(self, password: str, input_path: str, mode: str = 'CBC') -> str:
        """
        Encrypts data using AES encryption with the specified password and mode.

        This method encrypts the data from the given input file using AES encryption.
        The encryption process generates an AES key, which is then used to encrypt the file.
        The derived AES key is returned in hexadecimal format.

        Args:
            password (str): The password or key used for AES encryption.
            input_path (str): The path to the file to be encrypted.
            mode (str, optional): The AES encryption mode. Defaults to 'CBC'. Supported modes depend on the AES implementation.

        Returns:
            str: The AES key used for encryption, represented as a hexadecimal string.

        Raises:
            ValueError: If the AES key cannot be retrieved or if any other error occurs during encryption.
        """
        # Initialize AES encryptor
        aes_encryptor = AES_Encryption(password_or_key=password, mode=mode.upper())

        try:
            aes_key = aes_encryptor.encrypt(input_path=input_path, output_path=input_path)

            if not aes_key:
                raise ValueError("Failed to retrieve the AES derived key after encryption.")
            
            return aes_key.hex()
        
        except Exception as e:
            raise ValueError(f"An error occurred during AES encryption: {e}")
      

    def aes_decrypt_data(self, password: str, input_path: str, mode: str = 'CBC') -> None:
        """
        Decrypts data using AES decryption with the specified password and mode.

        This method decrypts the encrypted data in the given input file using AES decryption.
        The password provided is used to derive the decryption key. The decrypted data is saved
        back to the same file, overwriting the original encrypted content.

        Args:
            password (str): The password or key used for AES decryption.
            input_path (str): The path to the encrypted file to be decrypted.
            mode (str, optional): The AES decryption mode. Defaults to 'CBC'. Supported modes depend on the AES implementation.

        Raises:
            ValueError: If any error occurs during decryption (e.g., incorrect password, file issues, etc.).
        """
        # Initialize AES decryptor
        aes_decryptor = AES_Encryption(password_or_key=password, mode=mode.upper())

        try:
            aes_decryptor.decrypt(input_path, input_path)

        except Exception as e:
            raise ValueError(f"An error occurred during AES decryption: {e}")

    # ------------------------------------- RSA ENCRYPTION/DECRYPTION HANDLERS -------------------------------------
    
    def rsa_encrypt_key(self, plaintext: str, output_folder: str = 'encrypted_keys') -> None:
        """
        Encrypts an AES key using RSA public key encryption and saves the result to a file.

        This method takes an AES key in hexadecimal string format, validates and converts it to bytes,
        and then encrypts it using RSA public key encryption. The RSA keys are generated, saved, and the
        public key is used to encrypt the AES key. The resulting encrypted AES key is saved to a specified
        output folder.

        Args:
            plaintext (str): The AES key in hexadecimal format to be encrypted using RSA.
            output_folder (str, optional): The folder where the encrypted key file will be saved. Defaults to 'encrypted_keys'.

        Raises:
            ValueError: If the input plaintext is not a valid hexadecimal string.
            FileNotFoundError: If there are issues with file paths during the encryption process.
            OSError: If there are issues with file system operations (e.g., folder creation).
            Exception: If any other unexpected errors occur during the encryption process.
        """
        try:
            # Validate plaintext (AES key in hex format)
            aes_key_bytes = bytes.fromhex(plaintext)
            
            # Ensure the output folder exists
            output_path = os.path.abspath(output_folder)
            os.makedirs(output_path, exist_ok=True)

            # Initialize RSA encryptor
            rsa_encryptor = RSA_Encryption()
                
            # Generate and save RSA keys
            rsa_encryptor.generate_keys()
            rsa_encryptor.save_keys()

            # Load the public key
            public_key, _ = rsa_encryptor.load_keys()

            # Encrypt the AES key using the RSA public key
            ciphertext = rsa_encryptor.encrypt_data(plaintext=aes_key_bytes, public_key=public_key)

            # Save the encrypted AES key to a file
            encrypted_key_path = os.path.join(output_path, "encrypted_key.txt")
            with open(encrypted_key_path, "wb") as f:
                f.write(ciphertext)

        except ValueError as ve:
            logging.error(f"Input validation error: {ve}")
            raise
        except FileNotFoundError as fnfe:
            logging.error(f"File not found error during RSA encryption: {fnfe}")
            raise
        except OSError as oe:
            logging.error(f"File system error: {oe}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred during RSA encryption: {e}")
            raise


    def rsa_decrypt_key(self, encrypted_key_path: str, private_key_path: str) -> str:
        """
        Decrypts an encrypted AES key using RSA private key decryption.

        This method reads an encrypted AES key from the specified file, loads the RSA private key from 
        the given path, and uses the private key to decrypt the AES key. The decrypted key is then 
        returned in hexadecimal format.

        Args:
            encrypted_key_path (str): The file path where the encrypted AES key is stored.
            private_key_path (str): The file path where the RSA private key is stored.

        Returns:
            str: The decrypted AES key in hexadecimal format.

        Raises:
            FileNotFoundError: If either the encrypted key file or the private key file cannot be found.
            ValueError: If there are issues with loading the keys or decrypting the data.
            Exception: If any other unexpected errors occur during the decryption process.
        """
        try:
            # Validate and load the encrypted AES key
            if not os.path.exists(encrypted_key_path):
                raise FileNotFoundError(f"Encrypted key file not found: {encrypted_key_path}")
            with open(encrypted_key_path, "rb") as f:
                encrypted_key = f.read()

            # Validate and load the private key
            if not os.path.exists(private_key_path):
                raise FileNotFoundError(f"Private key file not found: {private_key_path}")
            rsa_encryptor = RSA_Encryption()
            _, private_key = rsa_encryptor.load_keys(folder_path=os.path.dirname(private_key_path))

            # Decrypt the AES key
            decrypted_key_bytes = rsa_encryptor.decrypt_data(ciphertext=encrypted_key, private_key=private_key)

            # Convert decrypted key to hexadecimal format
            decrypted_key_hex = decrypted_key_bytes.hex()
            return decrypted_key_hex

        except FileNotFoundError as fnfe:
            logging.error(f"File not found error: {fnfe}")
            raise
        except ValueError as ve:
            logging.error(f"Validation or decryption error: {ve}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred during decryption: {e}")
            raise

    # ---------------------------- MAIN ENCRYPTION AND DECRYPTION FUNCTIONS ----------------------------

    def encrypt(self, password: str, input_path: str, mode: str ='CBC') -> None:
        """
        Encrypts a file using a hybrid AES-RSA encryption scheme.

        This method first encrypts the contents of the specified file using AES encryption with a 
        provided password. The derived AES key is then encrypted using RSA and stored securely. 
        The encrypted file and AES key can later be decrypted using the corresponding private RSA key.

        Args:
            password (str): The password to derive the AES key. Must be a non-empty string.
            input_path (str): The path to the file to be encrypted. The file is overwritten with the 
                            encrypted data.
            mode (str, optional): The AES encryption mode. Defaults to 'CBC'. Supported modes depend 
                                on the AES implementation.

        Raises:
            ValueError: If the provided password is invalid or empty.
            FileNotFoundError: If the input file does not exist.
            PermissionError: If the application lacks the necessary permissions to access the input file.
            Exception: For any other unexpected errors during the encryption process.
        """
        try:
            if not isinstance(password, str) or not password.strip():
                raise ValueError("Password must be a non-empty string.")
        
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"The file or path '{input_path}' does not exist.")

            # Step 1: Encrypt the data using AES and derive the AES key
            aes_key = self.aes_encrypt_data(password=password, input_path=input_path, mode=mode.upper())

            # Step 2: Encrypt the AES key using RSA
            self.rsa_encrypt_key(plaintext=aes_key)

        except FileNotFoundError as fnfe:
            raise FileNotFoundError(f"Path error: {fnfe}")
        except PermissionError as pe:
            raise PermissionError(f"Permission error during encryption: {pe}")
        except ValueError as ve:
            raise ValueError(f"Validation error: {ve}")
        except Exception as e:
            raise Exception(f"Encryption process failed: {e}") from e


    def decrypt(self, encrypted_data_path: str, encrypted_key_path: str, private_key_path: str, mode: str ='CBC') -> None:
        """
        Decrypts encrypted data using a hybrid AES-RSA decryption scheme.

        This method first decrypts the AES key using the RSA private key and the provided encrypted AES key.
        The decrypted AES key is then used to decrypt the encrypted data, restoring it to its original form.
        The decrypted data is written to the same path as the encrypted data file.

        Args:
            encrypted_data_path (str): The path to the file containing the encrypted data.
            encrypted_key_path (str): The path to the file containing the encrypted AES key.
            private_key_path (str): The path to the RSA private key used for decrypting the AES key.
            mode (str, optional): The AES decryption mode. Defaults to 'CBC'. Supported modes depend on the AES implementation.

        Raises:
            FileNotFoundError: If any of the provided paths do not exist.
            PermissionError: If the application lacks the necessary permissions to access the files.
            ValueError: If the decrypted AES key is invalid or empty.
            Exception: For any other unexpected errors during the decryption process.
        """
        try:
            for path, description in [
                (encrypted_data_path, "encrypted data file"),
                (encrypted_key_path, "encrypted AES key file"),
                (private_key_path, "private key file")
            ]:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"The {description} '{path}' does not exist.")

            # Step 1: Decrypt the AES key using RSA
            decrypted_aes_key = self.rsa_decrypt_key(encrypted_key_path=encrypted_key_path, private_key_path=private_key_path)

            # Validate password
            if not isinstance(decrypted_aes_key, str) or not decrypted_aes_key.strip():
                raise ValueError("Password must be a non-empty string.")
            
            # Convert hex decrypted_aes_key to bytes
            decrypted_aes_key = bytes.fromhex(decrypted_aes_key)

            # Step 2: Decrypt the data using AES
            self.aes_decrypt_data(password=decrypted_aes_key, input_path=encrypted_data_path, mode=mode.upper())

        except FileNotFoundError as fnfe:
            raise FileNotFoundError(f"Path error: {fnfe}")
        except PermissionError as pe:
            raise PermissionError(f"Permission error during decryption: {pe}")
        except ValueError as ve:
            raise ValueError(f"Validation error: {ve}")
        except Exception as e:
            raise Exception(f"Decryption process failed: {e}") from e

