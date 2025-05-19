import os
import sys
import time

from PySecrypt.modules.encryption.asymmetrical.RSA import RSA_Encryption
from PySecrypt.modules.encryption.hybrid.AES_ECC import AESECC_Hybrid
from PySecrypt.modules.encryption.hybrid.AES_RSA import AESRSA_Hybrid
from PySecrypt.modules.encryption.symmetrical.AES import AES_Encryption
from PySecrypt.modules.encryption.symmetrical.ChaCha20 import ChaCha20_Encryption

# ------------------- SYMMETRIC ENCRYPTION HANDLERS -------------------

def handle_aes(args):
    """
    Handle AES encryption/decryption.
    """
    mode = args.mode if args.mode else 'cbc'
        
    # Validate input path
    if not os.path.exists(args.input):
        sys.exit(f"Error: The path '{args.input}' does not exist.")

    full_path = os.path.abspath(args.input)

    # Initialize AES encryption with the selected mode
    encryptor = AES_Encryption(password_or_key=get_password(), mode=mode.upper())

    start_time = time.time()

    if args.action == "encrypt":
        encryptor.encrypt(full_path, full_path)

    elif args.action == "decrypt":
        encryptor.decrypt(full_path, full_path)

    else:
        sys.exit(f"Error: Unsupported action '{args.action}'. Choose 'encrypt' or 'decrypt'.")

    end_time = time.time()
    full_time = end_time - start_time
    print(f"Finished in {full_time:.4f} seconds.\n")


def handle_chacha20(args):
    """
    Handle ChaCha20 encryption/decryption.
    """
    # Validate input path
    if not os.path.exists(args.input):
        sys.exit(f"Error: The path '{args.input}' does not exist.")

    # Determine if input is a file or folder
    full_path = os.path.abspath(args.input)

    # Initialize ChaCha20 encryption
    encryptor = ChaCha20_Encryption(password=get_password())

    start_time = time.time()

    if args.action == "encrypt":
        encryptor.encrypt(full_path, full_path)

    elif args.action == "decrypt":
        encryptor.decrypt(full_path, full_path)

    else:
        sys.exit(f"Error: Unsupported action '{args.action}'. Choose 'encrypt' or 'decrypt'.")

    end_time = time.time()
    full_time = end_time - start_time
    print(f"Finished in {full_time:.4f} seconds.\n")

# ------------------- ASYMMETRIC ENCRYPTION HANDLERS -------------------

def handle_rsa(args):
    """
    Handle RSA encryption/decryption.
    """
    encryptor = RSA_Encryption()

    start_time = time.time()

    if args.action == "generate":
        encryptor.generate_keys()
        encryptor.save_keys()

    elif args.action == "encrypt":
        try:
            plaintext = None

            if args.plain:
                # if user provides text directly then convert the string to bytes
                plaintext = args.plain.encode('utf-8')

            elif args.input:
                full_path = os.path.abspath(args.input)
                if os.path.isfile(full_path):
                    with open(full_path, "rb") as file:
                        plaintext = file.read()  # Read the file's contents into plaintext

                elif os.path.isdir(full_path):
                    raise ValueError("Provided input is a directory. Please specify a valid file.")
                
                else:
                    raise FileNotFoundError(f"Input file not found: {full_path}")

            # Ensure the plaintext variable is not empty
            if not plaintext or not plaintext.strip():
                raise ValueError("Plaintext is empty. Provide valid text or a valid input file.")

            # Check if the key argument is provided
            if not args.key:
                raise ValueError("No key specified. Provide a key with the --key option.")
            
            # Attempt to load the public key
            public_key, _ = encryptor.load_keys(args.key)

            # Attempt to encrypt the plaintext
            ciphertext = encryptor.encrypt_data(plaintext, public_key)
            ciphertext_hex = ciphertext.hex()

            # Create the rsa_output folder if it doesn't exist
            output_folder = "rsa_output"
            os.makedirs(output_folder, exist_ok=True)

            # Define the file path for saving the encrypted data
            encrypted_file_path = os.path.join(output_folder, "ciphertext.enc")

            # Write the encrypted ciphertext to the file (in hexadecimal)
            with open(encrypted_file_path, "w") as file:
                file.write(ciphertext_hex)           

        except FileNotFoundError as fnf_error:
            print(f"Error: Key file not found. Ensure the path is correct. Details: {fnf_error}")

        except ValueError as value_error:
            print(f"Error: {value_error}")

        except Exception as general_error:
            print(f"An unexpected error occurred: {general_error}")
    
    elif args.action == "decrypt":
        try:
            ciphertext = None

            # Ensure the private key is provided
            if not args.key:
                raise ValueError("No private key specified. Provide a key with the --key option.")

            # Load the private key
            _, private_key = encryptor.load_keys(args.key)

            if args.plain:
                # Convert hex string to bytes
                try:
                    ciphertext = bytes.fromhex(args.plain)
                    
                except ValueError:
                    raise ValueError("Invalid ciphertext format. Ensure it is a valid hexadecimal string.")

            elif args.input:
                full_path = os.path.abspath(args.input)
                if os.path.isfile(full_path):
                    if not full_path.endswith('.enc'):
                        raise ValueError("File does not appear to be encrypted. File must end with '.enc'.")
                    
                    with open(full_path, "r") as file:
                        ciphertext_hex = file.read()
                        ciphertext = bytes.fromhex(ciphertext_hex)
                
                elif os.path.isdir(full_path):
                    raise ValueError("Invalid input for RSA encryption: Only files or plaintext are allowed. Directories cannot be processed.")
                
                else:
                    raise FileNotFoundError(f"Input file not found: {full_path}")

            if not ciphertext:
                raise ValueError("Ciphertext is empty. Provide valid encrypted data or file.")

            # Verify ciphertext length matches key size
            expected_length = private_key.key_size // 8
            if len(ciphertext) != expected_length:
                raise ValueError(
                    f"Invalid ciphertext size. Decoded ciphertext length ({len(ciphertext)} bytes) "
                    f"does not match RSA key size ({expected_length} bytes)."
                )

            # Decrypt the ciphertext
            plaintext_bytes = encryptor.decrypt_data(ciphertext, private_key)
            plaintext = plaintext_bytes.decode('utf-8')

            # Save the decrypted plaintext
            output_folder = "rsa_output"
            os.makedirs(output_folder, exist_ok=True)
            decrypted_file_path = os.path.join(output_folder, "plaintext.txt")
            with open(decrypted_file_path, "w") as file:
                file.write(plaintext)

        except FileNotFoundError as fnf_error:
            print(f"Error: Key file not found. Details: {fnf_error}")

        except ValueError as value_error:
            print(f"Error: {value_error}")

        except Exception as general_error:
            print(f"An unexpected error occurred: {general_error}")

    else:
        sys.exit(f"Error: Unsupported action '{args.action}'. Choose 'encrypt', 'decrypt' or 'generate'.")

    end_time = time.time()
    full_time = end_time - start_time
    print(f"Finished in {full_time:.4f} seconds.\n")

# ------------------- HYBRID ENCRYPTION HANDLERS -------------------

def hybrid_rsa_aes(args):
    """
    Handle AES-RSA hybrid encryption/decryption.
    """
    mode = args.mode if args.mode else 'cbc'

    # Validate input path
    if not os.path.exists(args.input):
        sys.exit(f"Error: The path '{args.input}' does not exist.")

    full_path = os.path.abspath(args.input)

    # Initialize the hybrid encryption class
    hybrid_encryptor = AESRSA_Hybrid()

    start_time = time.time()

    if args.action == "encrypt":
        if args.key:
            raise ValueError("Path to encrypted keys directory is not needed during encryption. Provide it only during decryption")

        hybrid_encryptor.encrypt(get_password(), full_path, mode.upper())

    elif args.action == "decrypt":
        if not args.key:
            raise ValueError("You must provide a path to the folder that contains the RSA private key and the encrypted AES key.")
        
        full_keypath = os.path.abspath(args.key)
        encrypted_key_path = os.path.join(full_keypath, "encrypted_key.txt")
        private_key_path = os.path.join(full_keypath, "private_key.pem")

        hybrid_encryptor.decrypt(full_path, encrypted_key_path, private_key_path, mode.upper())

    else:
        sys.exit(f"Error: Unsupported action '{args.action}'. Choose 'encrypt' or 'decrypt'.")

    end_time = time.time()
    full_time = end_time - start_time
    print(f"Finished in {full_time:.4f} seconds.\n")


def hybrid_ecc_aes(args):
    """
    Handle AES-ECC hybrid encryption/decryption.
    """
    mode = args.mode if args.mode else 'cbc'

    # Validate input path
    if not os.path.exists(args.input):
        sys.exit(f"Error: The path '{args.input}' does not exist.")

    full_path = os.path.abspath(args.input)

    # Initialize the hybrid encryption class
    hybrid_encryptor = AESECC_Hybrid()

    start_time = time.time()

    if args.action == "encrypt":
        recipient_private_key, recipient_public_key = hybrid_encryptor.generate_ecc_key_pair()

        hybrid_encryptor.encrypt(
            recipient_public_key=recipient_public_key,
            recipient_private_key=recipient_private_key,
            input_path=full_path,
            mode=mode.upper()
        )

    elif args.action == "decrypt":
        hybrid_encryptor.decrypt(
            input_path=full_path,
            mode=mode.upper()
        )

    else:
        sys.exit(f"Error: Unsupported action '{args.action}'. Choose 'encrypt' or 'decrypt'.")

    end_time = time.time()
    full_time = end_time - start_time
    print(f"Finished in {full_time:.4f} seconds.\n")

# -------------------------------------- PASSWORD HANDLING --------------------------------------

def get_password():
    """
    Prompt the user to enter a password for encryption/decryption.
    Returns:
        str: The confirmed password.
    """
    print("You need to set a password for encrypting/decrypting your files.")
    while True:
        password = input("Enter a secure password: ").strip()
        if not password:
            print("Password cannot be empty. Please try again.")
            continue
        return password

