import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AESECC_Hybrid:
    """
    A class implementing hybrid encryption using Elliptic Curve Cryptography (ECC) for key exchange and AES for encryption.

    ### Features:
    - Uses ECC (ECDH) to derive a shared secret key.
    - Encrypts and decrypts data with AES in CBC, CTR, or GCM modes.
    - Supports file and folder encryption and decryption.
    - Saves and loads encryption assets (ephemeral public keys, nonces) for secure key exchange.

    ### Attributes:
    - `curve` (ec.EllipticCurve): The elliptic curve for ECC operations (default: SECP256R1).
    - `backend` (cryptography.hazmat.backends.Backend): Cryptographic backend for key generation and encryption.

    ### Methods:
    - `generate_ecc_key_pair`: Generates ECC private-public key pair.
    - `derive_shared_secret`: Derives shared AES key using ECC key exchange.
    - `generate_nonce`: Generates nonce for AES encryption based on mode.
    - `encrypt_file`: Encrypts a file using AES.
    - `decrypt_file`: Decrypts a file using AES.
    - `encrypt_folder`: Encrypts a folder by encrypting each file.
    - `decrypt_folder`: Decrypts a folder by decrypting each file.
    - `encrypt`: Encrypts file/folder using ECC for key exchange and AES for encryption.
    - `decrypt`: Decrypts file/folder using private key and saved encryption assets.
    """

    def __init__(self):
        """
        Initializes an AESECC_Hybrid instance with default cryptographic parameters.

        This constructor sets up the hybrid encryption system with the following defaults:
        - Elliptic Curve: SECP256R1, a widely used curve for secure cryptographic operations.
        - Cryptographic Backend: The default cryptographic backend provided by the `cryptography` library.

        These defaults ensure compatibility and security for performing elliptic curve operations and key exchanges.
        """
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

    # ------------------------------------------- KEY HANDLERS -------------------------------------------

    def generate_ecc_key_pair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Generates a new Elliptic Curve Cryptography (ECC) key pair using the SECP256R1 curve.

        This method leverages the SECP256R1 elliptic curve to generate a private-public key pair 
        that can be used for secure key exchange or digital signatures. The private key is kept secret, 
        while the public key can be shared with others for secure communications.

        Returns:
            tuple: A tuple containing:
                - ec.EllipticCurvePrivateKey: The generated private key.
                - ec.EllipticCurvePublicKey: The corresponding public key.

        Raises:
            ValueError: If there is an issue with key generation (e.g., failure to access the cryptographic backend).
        """
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key


    def derive_shared_secret(self, private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH) and the HKDF key derivation function.

        This method facilitates secure key exchange by using the local private key and the remote peer's 
        public key to compute a shared secret. The derived shared secret is then processed using the 
        HMAC-based Key Derivation Function (HKDF) to produce a symmetric key, which can be used for 
        encryption and decryption (e.g., for AES encryption).

        Arguments:
            private_key (ec.EllipticCurvePrivateKey): The private key of the local party used in the key exchange.
            peer_public_key (ec.EllipticCurvePublicKey): The public key of the remote party to compute the shared secret.

        Returns:
            bytes: A derived shared secret that is used as a key for AES encryption.

        Raises:
            ValueError: If the key exchange process fails, such as invalid key format or cryptographic errors.
            TypeError: If the provided keys are not of the expected types.
        """
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-encryption",
            backend=self.backend
        ).derive(shared_key)
        return derived_key


    def generate_nonce(self, mode: str) -> bytes:
        """
        Generates a cryptographically secure nonce (or initialization vector) for AES encryption.

        This method produces a nonce tailored to the specified encryption mode, ensuring compatibility 
        with the mode's requirements. The nonce is essential for achieving semantic security in encryption 
        by ensuring that identical plaintexts result in different ciphertexts.

        Arguments:
            mode (str): The encryption mode for which the nonce is being generated. Supported modes include:
                - "GCM": Generates a 12-byte (96-bit) nonce suitable for AES-GCM.
                - "CTR" or "CBC": Generates a 16-byte (128-bit) nonce suitable for AES-CTR or AES-CBC.

        Returns:
            bytes: A randomly generated nonce of the appropriate length for the specified mode.

        Raises:
            ValueError: If the provided mode is unsupported or invalid.
        """
        if mode == "GCM":
            return os.urandom(12)  # 96-bit nonce for GCM
        elif mode == "CTR" or mode == "CBC":
            return os.urandom(16)  # 128-bit IV for AES-CTR and AES-CBC
        else:
            raise ValueError("Unsupported mode for nonce generation")

    # ------------------------------------------ FILE HANDLERS -------------------------------------------

    def _save_files(self, ephemeral_public_bytes: bytes, nonce: bytes | None, recipient_private_key: ec.EllipticCurvePrivateKey) -> None:
        """
        Saves encryption-related assets to the filesystem.

        This method securely saves the following assets to the "encryption_assets" directory:
        - Ephemeral public key: Stored in PEM format.
        - Recipient's private key: Stored in PEM format without encryption.
        - Nonce (if provided): Stored as raw binary data.

        The directory is created if it does not exist. Each file is saved in a secure and structured manner 
        to facilitate later retrieval during decryption or key exchange.

        Arguments:
            ephemeral_public_bytes (bytes): The ephemeral public key in bytes format.
            nonce (bytes | None): The nonce used in encryption, or `None` if no nonce is used.
            recipient_private_key (ec.EllipticCurvePrivateKey): The recipient's private key.

        Raises:
            OSError: If an error occurs during file writing or directory creation.
        """
        assets_path = "encryption_assets"
    
        # Create the directory if it doesn't exist
        if not os.path.exists(assets_path):
            os.makedirs(assets_path)

        try:
            # Save ephemeral public key
            with open(os.path.join(assets_path, "ephemeral_public.pem"), "wb") as f:
                f.write(ephemeral_public_bytes)

            # Save recipient private key
            with open(os.path.join(assets_path, "recipient_private_key.pem"), "wb") as f:
                f.write(
                    recipient_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            # Save nonce if it exists
            if nonce is not None:
                with open(os.path.join(assets_path, "nonce.bin"), "wb") as f:
                    f.write(nonce)

            logging.info(f"Encryption assets successfully saved in directory: {assets_path}")
        except OSError as e:
            logging.error(f"Error saving file. File: {os.path.join(assets_path, 'ephemeral_public.pem')}, Error: {e}")
            logging.exception("Exception details")
            raise


    def _load_files(self) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes | None]:
        """
        Loads encryption-related assets from the filesystem.

        This method retrieves the following assets from the "encryption_assets" directory:
        - Recipient's private key: Loaded from a PEM file and deserialized.
        - Ephemeral public key: Loaded as raw bytes.
        - Nonce (if present): Loaded as raw binary data. If the nonce file is missing, `None` is returned.

        The loaded assets are essential for decrypting data or completing key exchange operations.

        Returns:
            tuple: A tuple containing:
                - ec.EllipticCurvePrivateKey: The recipient's private key.
                - bytes: The ephemeral public key in bytes format.
                - bytes | None: The nonce, or `None` if no nonce file is found.

        Raises:
            FileNotFoundError: If required files (e.g., private key or public key) are missing.
            OSError: If an error occurs during file reading.
            ValueError: If the private key or data cannot be parsed.
        """
        try:
            assets_path = "encryption_assets"
            nonce = None

            # Load the recipient's private key
            recipient_private_key_path = os.path.join(assets_path, "recipient_private_key.pem")
            with open(recipient_private_key_path, "rb") as f:
                recipient_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=self.backend
                )

            # Load the ephemeral public key
            ephemeral_public_path = os.path.join(assets_path, "ephemeral_public.pem")
            with open(ephemeral_public_path, "rb") as f:
                ephemeral_public_bytes = f.read()

            # Attempt to load the nonce, return None if the file doesn't exist
            nonce_path = os.path.join(assets_path, "nonce.bin")
            if os.path.exists(nonce_path):
                with open(nonce_path, "rb") as f:
                    nonce = f.read()

            logging.info(f"Encryption assets successfully loaded from directory: {assets_path}")
            return recipient_private_key, ephemeral_public_bytes, nonce

        except (FileNotFoundError, OSError) as e:
            logging.error(f"Error loading encryption data: {e}")
            raise
        except ValueError as e:
            logging.error(f"Error parsing private key or data: {e}")
            raise

    # ------------------------------------------ HELPER METHODS ------------------------------------------

    def encrypt_file(self, aes_key: bytes, input_path: str, output_path: str, mode: str = "CBC") -> bytes:
        """
        Encrypts a file using AES encryption in the specified mode.

        This method reads plaintext from a file, encrypts it using AES with the provided key and mode, 
        and writes the ciphertext to an output file. A nonce (or IV) is generated for encryption and returned.

        Supported modes:
        - CBC: Cipher Block Chaining
        - GCM: Galois/Counter Mode
        - CTR: Counter Mode

        Arguments:
            aes_key (bytes): The AES key, which must be 16, 24, or 32 bytes long.
            input_path (str): Path to the plaintext file to be encrypted.
            output_path (str): Path to save the encrypted file.
            mode (str): The encryption mode. Default is "CBC".

        Returns:
            bytes: The nonce (or IV) used during encryption.

        Raises:
            ValueError: If the AES key length is invalid, the input file is missing, or the mode is unsupported.
            IOError: If there is an error reading or writing files.
        """
        mode = mode.upper()

        # Ensure the key is the correct length for AES
        if len(aes_key) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes in length")

        # Read the plaintext from the file
        try:
            with open(input_path, "rb") as f:
                plaintext = f.read()
        except FileNotFoundError:
            raise ValueError(f"Input file not found: {input_path}")
        except IOError as e:
            raise ValueError(f"Error reading input file: {e}")

        # Encrypt the plaintext based on the specified mode
        if mode == "GCM":
            aesgcm = AESGCM(aes_key)
            nonce = self.generate_nonce(mode)  # 96-bit nonce for GCM
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        elif mode == "CTR":
            nonce = self.generate_nonce(mode)  # 128-bit IV for AES-CTR
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        elif mode == "CBC":
            iv = self.generate_nonce(mode)  # 128-bit IV for AES-CBC
            padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes
            padded_data = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            nonce = iv  # In CBC, the IV is used as the nonce
        else:
            raise ValueError("Unsupported mode. Currently, only 'GCM', 'CTR', and 'CBC' are supported.")

        # Write the ciphertext to the output file
        try:
            output_dir = os.path.dirname(output_path)  # Get the directory part of the output path
            if output_dir and not os.path.exists(output_dir):  # Create the directory if it doesn't exist
                os.makedirs(output_dir)
            
            with open(output_path, "wb") as enc_file:
                enc_file.write(ciphertext)

        except IOError as e:
            raise ValueError(f"Error writing output file: {e}")

        # Return the nonce
        return nonce


    def decrypt_file(self, aes_key: bytes, input_path: str, output_path: str, nonce: bytes, mode: str = "CBC") -> None:
        """
        Decrypts a file encrypted with AES using the specified mode.

        This method reads ciphertext from a file, decrypts it using AES with the provided key, nonce, and mode, 
        and writes the plaintext to an output file.

        Supported modes:
        - CBC: Cipher Block Chaining
        - GCM: Galois/Counter Mode
        - CTR: Counter Mode

        Arguments:
            aes_key (bytes): The AES key, which must be 16, 24, or 32 bytes long.
            input_path (str): Path to the encrypted file to be decrypted.
            output_path (str): Path to save the decrypted file.
            nonce (bytes): The nonce (or IV) used during encryption.
            mode (str): The decryption mode. Default is "CBC".

        Raises:
            ValueError: If the AES key length, nonce length, or mode is invalid, or the input file is missing.
            IOError: If there is an error reading or writing files.
        """
        mode = mode.upper()

        # Ensure the key is the correct length for AES
        if len(aes_key) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes in length")
        
        # Validate the nonce length based on the mode
        if mode == "GCM" and len(nonce) != 12:
            raise ValueError("GCM mode requires a 12-byte nonce")
        elif mode in {"CTR", "CBC"} and len(nonce) != 16:
            raise ValueError("CTR and CBC modes require a 16-byte nonce")

        # Read the ciphertext from the file
        try:
            with open(input_path, "rb") as f:
                ciphertext = f.read()
        except FileNotFoundError:
            raise ValueError(f"Input file not found: {input_path}")
        except IOError as e:
            raise ValueError(f"Error reading input file: {e}")

        # Decrypt the ciphertext based on the specified mode
        if mode == "GCM":
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        elif mode == "CTR":
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=self.backend)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        elif mode == "CBC":
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(nonce), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding after decryption
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        else:
            raise ValueError("Unsupported mode. Currently, only 'GCM', 'CTR', and 'CBC' are supported.")

        # Write the decrypted plaintext to the output file
        try:
            output_dir = os.path.dirname(output_path)  # Get the directory part of the output path
            if output_dir and not os.path.exists(output_dir):  # Create the directory if it doesn't exist
                os.makedirs(output_dir)
            
            with open(output_path, "wb") as dec_file:
                dec_file.write(plaintext)
                
        except IOError as e:
            raise ValueError(f"Error writing output file: {e}")


    def encrypt_folder(self, aes_key: bytes, folder_path: str, mode: str = "CBC") -> None:
        """
        Encrypts all files in a folder using AES encryption in the specified mode.

        This method iterates through all files in the specified folder (and subfolders), encrypts each file 
        using AES, and saves the encrypted files in a new folder with "_encrypted" appended to the original folder name. 
        Each file's nonce is saved in a separate file alongside the encrypted file.

        Arguments:
            aes_key (bytes): The AES key, which must be 16, 24, or 32 bytes long.
            folder_path (str): Path to the folder containing files to be encrypted.
            mode (str): The encryption mode. Default is "CBC".

        Raises:
            ValueError: If the AES key length is invalid or the mode is unsupported.
            IOError: If there is an error reading or writing files.
        """
        encrypted_folder_path = folder_path + "_encrypted"
        os.makedirs(encrypted_folder_path, exist_ok=True)  # Ensure the encrypted folder exists

        logging.info(f"Starting encryption of folder: {folder_path}")

        for root, _, files in os.walk(folder_path):  # Walk through all files in the folder (and subfolders)
            for file in files:
                input_file_path = os.path.join(root, file)  # Full path to the file
                relative_path = os.path.relpath(input_file_path, folder_path)  # Get relative path from the folder
                output_file_path = os.path.join(encrypted_folder_path, relative_path + ".enc")  # Output encrypted file path

                # Create the directory for the encrypted file if it doesn't exist
                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                try:
                    # Encrypt the file and get the nonce
                    nonce = self.encrypt_file(aes_key, input_file_path, output_file_path, mode)

                    # Save the nonce to a separate file
                    with open(output_file_path + ".nonce", "wb") as nonce_file:
                        nonce_file.write(nonce)

                    logging.info(f"Encrypted file saved: {output_file_path}")
                except Exception as e:
                    logging.error(f"Error encrypting file {input_file_path}: {e}")

        logging.info(f"Encryption of folder {folder_path} completed.")


    def decrypt_folder(self, aes_key: bytes, folder_path: str, mode: str = "CBC") -> None:
        """
        Decrypts all files in a folder encrypted with AES using the specified mode.

        This method iterates through all encrypted files in the specified folder (and subfolders), decrypts each file 
        using AES, and saves the decrypted files in a new folder with "_decrypted" appended to the original folder name. 
        Each encrypted file's nonce is read from its corresponding `.nonce` file.

        Arguments:
            aes_key (bytes): The AES key, which must be 16, 24, or 32 bytes long.
            folder_path (str): Path to the folder containing encrypted files.
            mode (str): The decryption mode. Default is "CBC".

        Raises:
            ValueError: If the AES key length, nonce length, or mode is invalid.
            IOError: If there is an error reading or writing files, or if a nonce file is missing.
        """
        # Determine the decrypted folder path
        if folder_path.endswith("_encrypted"):
            decrypted_folder_path = folder_path.replace("_encrypted", "_decrypted")
        else:
            decrypted_folder_path = folder_path + "_decrypted"

        # Create the decrypted folder if it doesn't exist
        os.makedirs(decrypted_folder_path, exist_ok=True)
        logging.info(f"Starting decryption of folder: {folder_path}")

        # Iterate over all files in the folder
        for root, _, files in os.walk(folder_path):
            for file in files:
                # Skip nonce files
                if file.endswith(".nonce"):
                    continue

                input_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(input_file_path, folder_path)
                output_file_path = os.path.join(decrypted_folder_path, relative_path[:-4])  # Remove ".enc" suffix

                # Determine the path for the corresponding nonce file
                nonce_file_path = input_file_path + ".nonce"

                # Check if the nonce file exists and read it
                if not os.path.exists(nonce_file_path):
                    logging.error(f"Nonce file not found for {input_file_path}, skipping decryption.")
                    continue

                try:
                    with open(nonce_file_path, "rb") as nonce_file:
                        nonce = nonce_file.read()

                    # Ensure the output directory exists
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                    # Decrypt the file
                    self.decrypt_file(aes_key, input_file_path, output_file_path, nonce, mode)
                    logging.info(f"Decrypted file saved: {output_file_path}")

                except Exception as e:
                    logging.error(f"Error decrypting file {input_file_path}: {e}")

        logging.info(f"Decryption of folder {folder_path} completed.")

    # --------------------------------------- ENCRYPT/DECRYPT DATA ---------------------------------------

    def encrypt(self, recipient_public_key: ec.EllipticCurvePublicKey, recipient_private_key: ec.EllipticCurvePrivateKey, input_path: str, mode: str = "CBC") -> None:
        """
        Encrypts a file or folder using hybrid encryption, combining ECC key exchange and AES encryption.

        This method generates an ephemeral ECC key pair, derives a shared AES key using the recipient's public key,
        and encrypts the provided file or folder using the AES key in the specified mode. The encryption assets, including
        the ephemeral public key and nonce, are saved for use during decryption.

        Supported modes:
        - CBC: Cipher Block Chaining
        - GCM: Galois/Counter Mode
        - CTR: Counter Mode

        Arguments:
            recipient_public_key (ec.EllipticCurvePublicKey): The recipient's public key for deriving the shared AES key.
            recipient_private_key (ec.EllipticCurvePrivateKey): The recipient's private key, which is saved for decryption.
            input_path (str): Path to the file or folder to be encrypted.
            mode (str): The encryption mode. Default is "CBC".

        Raises:
            ValueError: If the input path is invalid, or if an unsupported input type or mode is provided.
            IOError: If there is an error reading or writing files.
        """
        logging.info("Starting encryption process...")
        logging.info(f"Encrypting using AES-{mode.upper()}...")

        try:
            # Check if the input path exists
            if not os.path.exists(input_path):
                raise ValueError(f"The path '{input_path}' does not exist.")

            # Generate an ephemeral ECC key pair
            ephemeral_private_key, ephemeral_public_key = self.generate_ecc_key_pair()

            # Derive shared secret using recipient's public key
            aes_key = self.derive_shared_secret(private_key=ephemeral_private_key, peer_public_key=recipient_public_key)
            nonce = None

            # Encrypt the input (file or folder)
            if os.path.isfile(input_path):
                encrypted_path = input_path + ".enc"
                nonce = self.encrypt_file(aes_key=aes_key, input_path=input_path, output_path=encrypted_path, mode=mode)

            elif os.path.isdir(input_path):
                self.encrypt_folder(aes_key, input_path, mode)

            else:
                raise ValueError("Unsupported input type. Only files and directories are supported.")

            # Serialize the ephemeral public key to share with the recipient
            ephemeral_public_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Save the encryption assets (ephemeral public key, nonce, recipient private key)
            self._save_files(ephemeral_public_bytes=ephemeral_public_bytes, nonce=nonce, recipient_private_key=recipient_private_key)
            logging.info("Encryption successful.\n")

        except ValueError as e:
            logging.error(f"Encryption failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during encryption: {e}")
            raise


    def decrypt(self, input_path: str, mode: str = "CBC") -> None:
        """
        Decrypts a file or folder that was encrypted using hybrid encryption with ECC and AES.

        This method loads the encryption artifacts (recipient private key, ephemeral public key, and nonce),
        derives the shared AES key using the recipient's private key and the ephemeral public key, and decrypts
        the provided file or folder using the AES key in the specified mode.

        Supported modes:
        - CBC: Cipher Block Chaining
        - GCM: Galois/Counter Mode
        - CTR: Counter Mode

        Arguments:
            input_path (str): Path to the encrypted file or folder.
            mode (str): The decryption mode. Default is "CBC".

        Raises:
            ValueError: If the input path is invalid, or if an unsupported input type, mode, or file extension is provided.
            IOError: If there is an error reading or writing files, or if decryption artifacts are missing.
        """
        logging.info("Starting decryption process...")
        logging.info(f"Decrypting using AES-{mode.upper()}...")

        # Validate input path
        if not os.path.exists(input_path):
            raise ValueError(f"The path '{input_path}' does not exist.")

        try:
            # Load encryption artifacts (private key, ephemeral public key, nonce)
            recipient_private_key, ephemeral_public_bytes, nonce = self._load_files()

            # Derive the AES key using the recipient's private key and ephemeral public key
            aes_key = self.derive_shared_secret(
                private_key=recipient_private_key,
                peer_public_key=serialization.load_pem_public_key(
                    ephemeral_public_bytes, backend=self.backend
                )
            )
            logging.info("Shared AES key derived successfully.")

            # Handle file decryption
            if os.path.isfile(input_path):
                if not input_path.endswith(".enc"):
                    raise ValueError("File does not have the expected '.enc' extension for encrypted files.")
                output_path = input_path[:-4]  # Remove '.enc' to get the decrypted file name
                self.decrypt_file(aes_key, input_path, output_path, nonce, mode)

            # Handle folder decryption
            elif os.path.isdir(input_path):
                if not input_path.endswith("_encrypted"):
                    raise ValueError("Folder does not have the expected '_encrypted' suffix for encrypted folders.")
                self.decrypt_folder(aes_key, input_path, mode)

            else:
                raise ValueError("Unsupported input type. Please provide a valid file or folder.")

            logging.info("Decryption successful.\n")

        except ValueError as e:
            logging.error(f"Decryption failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during decryption: {e}")
            raise

