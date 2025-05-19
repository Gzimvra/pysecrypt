import argparse

from PySecrypt.encryption_handlers import (
    handle_aes,
    handle_chacha20,
    handle_rsa,
    hybrid_ecc_aes,
    hybrid_rsa_aes,
)
from PySecrypt.utils.version_handler import show_version


def main():
    # Constants
    DEFAULTS = {"aes_mode": "cbc"}

    # Supported encryption techniques and modes
    supported_encryption_techniques = ["aes", "chacha20", "rsa", "aes-rsa", "aes-ecc"]
    supported_actions = ["encrypt", "decrypt", "generate"]
    supported_aes_modes = ["cbc", "ctr", "gcm"]

    # Create the argument parser
    parser = argparse.ArgumentParser(description="PySecrypt CLI Tool")

    # Global Flags
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show the version of the tool with additional information.",
        dest="version"
    )
    parser.add_argument(
        "-ciphers", 
        action="store_true", 
        help="Display a list of all supported encryption techniques, available actions, and AES encryption modes."
    )
    parser.add_argument(
        "-enc", 
        action="store_true", 
        help="Enable encryption functionality. Use this flag to indicate that encryption operations are to be performed."
    )
    
    # Global Arguments
    parser.add_argument(
        "-t", "--technique", 
        type=str, 
        metavar="STRING", 
        help="Specify the encryption technique to use. Choose from the available options (e.g., 'aes', 'rsa', 'chacha20')."
    )
    parser.add_argument(
        "-a", "--action", 
        type=str, 
        metavar="STRING", 
        choices=supported_actions, 
        help="Specify the action to perform with the selected technique. Choose from 'encrypt', 'decrypt', or 'generate'."
    )
    parser.add_argument(
        "-i", "--input", 
        type=str, 
        metavar="PATH", 
        help="Provide the input file or folder path to be processed for encryption or decryption."
    )
    parser.add_argument(
        "-m", "--mode", 
        type=str, 
        metavar="STRING", 
        choices=supported_aes_modes, 
        help="Specify the AES encryption mode to use. Choose from 'cbc', 'ctr', or 'gcm'. (Defaults to 'cbc' if not provided)."
    )
    parser.add_argument(
        "-p", "--plain", 
        type=str, 
        metavar="TEXT/BASE64", 
        help="Provide the plaintext (for encryption) or the base64-encoded ciphertext (for decryption)."
    )
    parser.add_argument(
        "-k", "--key", 
        type=str, 
        metavar="FOLDER_PATH", 
        help="Provide the path to a folder containing the 'public_key.pem' and 'private_key.pem' files for RSA or hybrid encryption/decryption."
    )

    args = parser.parse_args()

    # ---------------------- HELPER FUNCTIONS ----------------------

    def validate_args(args, required_args, unsupported_args=None):
        """
        Utility function to validate and set arguments for encryption techniques.
        """
        # Ensure required arguments are provided
        for arg, message in required_args.items():
            if not getattr(args, arg, None):
                parser.error(message)

        # Ensure unsupported arguments are not provided
        if unsupported_args:
            for arg, message in unsupported_args.items():
                if getattr(args, arg, None) is not None:
                    parser.error(message)

    def handle_encryption_args(args):
        """
        Validate and handle arguments for encryption techniques.
        """
        if not args.technique:
            parser.error("The '-t/--technique' argument is required. Specify an encryption technique (e.g., 'aes', 'rsa').")
        if args.technique not in supported_encryption_techniques:
            parser.error(f"Invalid technique '{args.technique}'. Supported techniques are: {', '.join(supported_encryption_techniques)}.")

        if args.technique == "aes":
            if not args.mode:
                args.mode = DEFAULTS["aes_mode"]
            validate_args(
                args,
                required_args={
                    "action": "The '-a/--action' argument is required for AES encryption.",
                    "input": "The '-i/--input' argument is required for AES encryption.",
                },
                unsupported_args={
                    "plain": "AES does not support the '-p/--plain' argument. Please provide input through a file or base64-encoded ciphertext.",
                    "key": "AES does not require the '-k/--key' argument.",
                },
            )

        elif args.technique == "chacha20":
            validate_args(
                args,
                required_args={
                    "action": "The '-a/--action' argument is required for ChaCha20 encryption.",
                    "input": "The '-i/--input' argument is required for ChaCha20 encryption.",
                },
                unsupported_args={
                    "mode": "ChaCha20 does not support the '-m/--mode' argument.",
                    "plain": "ChaCha20 does not support the '-p/--plain' argument. Provide the input through a file or base64-encoded ciphertext.",
                    "key": "ChaCha20 does not require the '-k/--key' argument.",
                },
            )

        elif args.technique == "rsa":
            if args.action == "generate":
                # If the action is 'generate', ensure no other arguments are provided
                if any(arg is not None for arg in [args.input, args.plain, args.key, args.mode]):
                    parser.error("For RSA key generation, no other arguments are required.")
            else:
                # Validate arguments for encryption or decryption
                validate_args(
                    args,
                    required_args={
                        "action": "The '-a/--action' argument is required for RSA encryption/decryption.",
                        "key": "The '-k/--key' argument (folder path to PEM key files) is required for RSA encryption/decryption.",
                    },
                    unsupported_args={"mode": "RSA does not support the '-m/--mode' argument."},
                )
                
                # Ensure that either '-i/--input' or '-p/--plain' is provided, but not both
                if not args.input and not args.plain:
                    parser.error("Either '-i/--input' (file/folder) or '-p/--plain' (plaintext) is required for RSA encryption/decryption.")
                
                if args.input and args.plain:
                    parser.error("Specify either '-i/--input' (file) or '-p/--plain' (plaintext), not both. Using both is not supported.")

        elif args.technique in ["aes-rsa", "aes-ecc"]:
            if not args.mode:
                args.mode = DEFAULTS["aes_mode"]

            if args.technique == "aes-rsa":
                if args.action == "decrypt":
                    unsupported_args = {
                        "plain": f"{args.technique} does not support the '-p/--plain' argument.",
                    }
                else:
                    unsupported_args = {
                        "plain": f"{args.technique} does not support the '-p/--plain' argument.",
                        "key": "-k/--key is not supported for this technique.",
                    }
            elif args.technique == "aes-ecc":
                unsupported_args = {
                    "plain": f"{args.technique} does not support the '-p/--plain' argument.",
                    "key": "-k/--key is not supported for this technique.",
                }

            validate_args(
                args,
                required_args={
                    "action": f"The '-a/--action' argument is required for {args.technique} encryption.",
                    "input": f"The '-i/--input' argument is required for {args.technique} encryption.",
                },
                unsupported_args=unsupported_args,
            )

        handle_encryption(args)

    # ---------------------- VALIDATION LOGIC ----------------------

    if (args.version and args.ciphers) or (args.version and args.enc) or (args.ciphers and args.enc):
        parser.error("You cannot use multiple flags at once. Please choose only one flag at a time.")

    if args.version:
        show_version()
    
    if args.ciphers:
        if any(getattr(args, arg) for arg in vars(args) if arg != "ciphers"):
            parser.error("The '-ciphers' command does not accept other arguments.")
        print("Supported Encryption Techniques and Options:")
        print("\nEncryption Techniques:")
        for technique in supported_encryption_techniques:
            print(f"  - {technique}")
        print("\nSupported Actions:")
        for action in supported_actions:
            print(f"  - {action}")
        print("\nAES Supported Modes:")
        for mode in supported_aes_modes:
            print(f"  - {mode}")
        exit(0)

    if args.enc:
        handle_encryption_args(args)

# -------------------------------------- ENCRYPTION HANDLER --------------------------------------

def handle_encryption(args):
    """
    Handle encryption and decryption based on the selected technique.
    """
    # Dispatch based on the encryption technique
    if args.technique == "aes":
        handle_aes(args)
    elif args.technique == "chacha20":
        handle_chacha20(args)
    elif args.technique == "rsa":
        handle_rsa(args)
    elif args.technique == "aes-rsa":
        hybrid_rsa_aes(args)
    elif args.technique == "aes-ecc":
        hybrid_ecc_aes(args)

