import logging
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class RSA_Encryption:
    """
    A class that provides RSA encryption and decryption functionality.

    This class facilitates the generation, serialization, and storage of RSA key pairs, 
    as well as the encryption and decryption of data using RSA. It allows for key management, 
    including generating, saving, loading, and retrieving keys, and it supports encrypting 
    and decrypting messages using the RSA public and private keys.

    Key Functionalities:
        - Generate RSA key pairs (public and private).
        - Serialize and return RSA keys in PEM format.
        - Save and load RSA keys to/from files.
        - Encrypt and decrypt data using RSA encryption with OAEP padding.

    Attributes:
        key_size (Optional[int]): The size of the RSA key pair in bits. Defaults to `None`.
        private_key (Optional[rsa.RSAPrivateKey]): The RSA private key. Defaults to `None`.
        public_key (Optional[rsa.RSAPublicKey]): The RSA public key. Defaults to `None`.

    Methods:
        __init__(): Initializes an RSA_Encryption object with default key size and empty keys.
        generate_keys(): Generates a new RSA key pair with a specified key size.
        return_keys(): Returns the public and private keys in PEM format.
        save_keys(): Saves the public and private keys to files in a specified folder.
        load_keys(): Loads RSA keys from specified files.
        encrypt_data(): Encrypts plaintext data using the public key with OAEP padding.
        decrypt_data(): Decrypts ciphertext data using the private key with OAEP padding.
    """

    def __init__(self):
        """
        Initializes an instance of the RSA_Encryption class.

        This constructor sets up the initial state of the class by initializing the key size, 
        private key, and public key to `None`. These attributes are later populated when 
        the keys are generated or loaded.

        Attributes:
            key_size (Optional[int]): The size of the RSA key pair in bits. Initially set to `None`.
            private_key (Optional[rsa.RSAPrivateKey]): The private key for encryption and decryption. Initially set to `None`.
            public_key (Optional[rsa.RSAPublicKey]): The public key for encryption. Initially set to `None`.
        """
        self.key_size = None
        self.private_key = None
        self.public_key = None

    # ----------------------------------------- HANDLE KEYS ------------------------------------------

    def generate_keys(self, key_size: int = 2048) -> None:
        """
        Generates a new RSA key pair (public and private keys) with the specified key size.
        
        This method creates a secure pair of keys using the RSA algorithm. The keys are stored
        within the instance of the class for further operations like encryption, decryption, and storage.

        Args:
            key_size (int): The size of the RSA key in bits. The value must be an integer 
                            greater than or equal to 1024. Default is 2048 bits, which is
                            considered secure for most applications.

        Raises:
            ValueError: Raised if the provided key size is invalid, such as being less than 
                        1024 or not an integer.
            Exception: Raised for unexpected errors during key generation, ensuring the caller 
                    is informed of failures.
        """ 
        try:
            # Validate key size
            if not isinstance(key_size, int) or key_size < 1024:
                raise ValueError("Key size must be an integer greater than or equal to 1024 bits.")

            self.key_size = key_size

            # Generate the private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard exponent for RSA encryption
                key_size=self.key_size  # Key size in bits
            )

            # Derive the public key from the private key
            self.public_key = self.private_key.public_key()

            logging.info(f"Keys generated successfully with size: {self.key_size} bits.")

        except ValueError as ve:
            logging.error(f"Invalid key size: {ve}")
            raise
        except Exception as e:
            logging.error(f"An error occurred during key generation: {e}")
            raise
        

    def return_keys(self) -> tuple[bytes, bytes]:
        """
        Retrieves the RSA key pair in serialized PEM format for secure storage or transmission.
        
        This method converts the RSA public and private keys into a standard PEM-encoded format,
        making them compatible with most cryptographic systems and storage requirements.

        Returns:
            tuple[bytes, bytes]: A tuple containing:
                - The public key in PEM format as bytes.
                - The private key in PEM format as bytes, without encryption.

        Raises:
            ValueError: Raised if the keys have not been generated yet, ensuring that
                        the method is only called after successful key generation.
            Exception: Raised for unexpected errors during the serialization process.
        """
        try:
            # Ensure the keys have been generated
            if self.public_key is None or self.private_key is None:
                raise ValueError("Keys have not been generated. Please generate the keys before retrieving them.")

            # Serialize the public key to PEM format (for sharing or storing)
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Serialize the private key to PEM format (for secure storage or usage)
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # No encryption on private key
            )
            
            logging.info("Keys serialized successfully.")
            return public_key_pem, private_key_pem
        
        except ValueError as ve:
            logging.error(f"Key retrieval error: {ve}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred during key serialization: {e}")
            raise


    def save_keys(self, folder_path: str = "encrypted_keys", public_key_name: str = "public_key.pem", private_key_name: str = "private_key.pem") -> None:
        """
        Saves the RSA public and private keys to the specified files in the provided directory.
        
        This method ensures that the keys are securely written to disk in PEM format. The directory
        is created if it does not already exist. Proper error handling ensures any issues during
        the saving process are reported.

        Args:
            folder_path (str): The directory where the key files will be saved. Default is "encrypted_keys".
            public_key_name (str): The filename for the public key. Default is "public_key.pem".
            private_key_name (str): The filename for the private key. Default is "private_key.pem".

        Raises:
            ValueError: Raised if the keys have not been generated, preventing saving invalid data.
            OSError: Raised for file system errors, such as permission issues or disk space limitations.
            Exception: Raised for unexpected errors during the key-saving process.
        """
        logging.info(f"Saving keys to '{folder_path}' directory...")
        try:
            if not self.private_key or not self.public_key:
                raise ValueError("Keys have not been generated yet.")
            
            # Ensure the folder exists
            os.makedirs(folder_path, exist_ok=True)

            # Define file paths
            public_key_path = os.path.abspath(os.path.join(folder_path, public_key_name))
            private_key_path = os.path.abspath(os.path.join(folder_path, private_key_name))

            # Save public key
            with open(public_key_path, 'wb') as pub_file:
                pub_file.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logging.info(f"Public key saved to {public_key_path}")

            # Save private key
            with open(private_key_path, 'wb') as priv_file:
                priv_file.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()  # Save without encryption
                ))
            logging.info(f"Private key saved to {private_key_path}")

        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            raise
        except OSError as oe:
            logging.error(f"File system error while saving keys: {oe}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred while saving keys: {e}")
            raise


    def load_keys(self, folder_path: str = "encrypted_keys", public_key_name: str = "public_key.pem", private_key_name: str = "private_key.pem") -> tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
        """
        Loads RSA public and private keys from files in the specified directory.
        
        This method deserializes keys stored in PEM format and makes them available as usable
        key objects for encryption and decryption. It validates the presence of the files and 
        ensures proper error reporting for missing or invalid files.

        Args:
            folder_path (str): The directory containing the key files. Default is "encrypted_keys".
            public_key_name (str): The filename of the public key. Default is "public_key.pem".
            private_key_name (str): The filename of the private key. Default is "private_key.pem".

        Returns:
            tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]: A tuple containing:
                - The public key as an RSAPublicKey object.
                - The private key as an RSAPrivateKey object.

        Raises:
            FileNotFoundError: Raised if one or both of the key files are missing in the specified directory.
            ValueError: Raised if the key files cannot be deserialized due to corruption or invalid format.
            Exception: Raised for unexpected errors during the key-loading process.
        """
        try:
            # Define the paths for the key files
            public_key_path = os.path.join(folder_path, public_key_name)
            private_key_path = os.path.join(folder_path, private_key_name)

            # Check if the files exist
            if not os.path.exists(public_key_path):
                logging.error(f"Public key file not found: {public_key_path}")
                raise FileNotFoundError(f"Public key file not found: {public_key_path}")
            if not os.path.exists(private_key_path):
                logging.error(f"Private key file not found: {private_key_path}")
                raise FileNotFoundError(f"Private key file not found: {private_key_path}")

            # Load the public key
            with open(public_key_path, 'rb') as pub_file:
                public_key = serialization.load_pem_public_key(pub_file.read())
            logging.info(f"Public key loaded successfully from {public_key_path}")

            # Load the private key
            with open(private_key_path, 'rb') as priv_file:
                private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
            logging.info(f"Private key loaded successfully from {private_key_path}")

            # Return the deserialized key objects
            return public_key, private_key
        
        except FileNotFoundError as fnfe:
            logging.error(f"File not found error: {fnfe}")
            raise
        except ValueError as ve:
            logging.error(f"Key deserialization error: {ve}")
            raise ValueError(f"Failed to deserialize keys: {ve}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading keys: {e}")
            raise

    # ------------------------------------- ENCRYPT/DECRYPT DATA -------------------------------------

    def encrypt_data(self, plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypts plaintext using the RSA public key with OAEP padding and SHA-256 hashing.
        
        This method ensures secure encryption by limiting plaintext size to the key's capabilities,
        applying optimal asymmetric encryption padding (OAEP), and using SHA-256 for the hashing algorithm.

        Args:
            plaintext (bytes): The plaintext data to be encrypted. Its size must not exceed the
                            maximum allowable size for the RSA key and padding scheme.
            public_key (rsa.RSAPublicKey): The public key used for encryption. Must be generated or loaded.

        Returns:
            bytes: The encrypted ciphertext.

        Raises:
            ValueError: Raised if:
                - The public key is not provided.
                - The plaintext exceeds the maximum allowable size for encryption.
            Exception: Raised for unexpected errors during the encryption process.
        """
        logging.info("Starting encryption process...")
        logging.info(f"Encrypting using RSA...")
        
        if not public_key:
            raise ValueError("Public key is not available. Generate or load keys first.")
        
        # Calculate the maximum plaintext size based on the key size and padding overhead
        key_size_bytes = public_key.key_size // 8
        hash_size_bytes = hashes.SHA256().digest_size  # Use the digest size from the hash function
        max_size = key_size_bytes - 2 * hash_size_bytes - 2  # OAEP padding size

        # Check if the plaintext fits within the maximum size
        if len(plaintext) > max_size:
            raise ValueError(
                f"Plaintext size exceeds maximum allowable limit for RSA encryption. "
                f"Provided size: {len(plaintext)} bytes, Max size: {max_size} bytes."
            )
        logging.info(f"Plaintext size: {len(plaintext)} bytes, Max size: {max_size} bytes")

        try:
            # Encrypt the plaintext using the public key with OAEP padding
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logging.info("RSA encryption successful.\n")
            return ciphertext
        
        except Exception as e:
            logging.error(f"An error occurred during RSA encryption: {e}")
            raise ValueError(f"Encryption failed: {e}")


    def decrypt_data(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decrypts ciphertext using the RSA private key with OAEP padding and SHA-256 hashing.
        
        This method securely decrypts data encrypted with the corresponding public key. It ensures
        proper error handling for invalid keys, incorrect ciphertext, or decryption failures.

        Args:
            ciphertext (bytes): The encrypted data to be decrypted.
            private_key (rsa.RSAPrivateKey): The private key used for decryption. Must be generated or loaded.

        Returns:
            bytes: The decrypted plaintext as bytes.

        Raises:
            ValueError: Raised if:
                - The private key is not provided.
                - Decryption fails due to invalid ciphertext or mismatched keys.
            Exception: Raised for unexpected errors during the decryption process.
        """
        logging.info("Starting decryption process...")
        logging.info(f"Decrypting using RSA...")

        if not private_key:
            raise ValueError("Private key is not available. Generate or load keys first.")
        
        try:
            # Decrypt the ciphertext using the private key
            plaintext_bytes = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logging.info("RSA decryption successful.\n")           
            return plaintext_bytes

        except Exception as e:
            logging.error(f"An error occurred during RSA decryption: {e}")
            raise ValueError(f"Decryption failed: {e}")

