# RCS Tool Documentation

## Overview

The RCS tool is a text encryption utility based on the RC4 encryption algorithm. It allows users to encrypt and decrypt text using custom keys, manage encryption keys, and maintain a history of encrypted and decrypted messages. The tool supports various commands for managing keys, checking for updates, and performing brute-force decryption attempts.

### Features

- **Encrypt and Decrypt Text:** Securely encrypt and decrypt text using the RC4 algorithm with custom keys.
- **Key Management:** Easily add, delete, and display encryption keys.
- **History Management:** Maintain and display a history of encrypted and decrypted messages.
- **Update Notifications:** Check for updates and notify users of new versions.
- **Configuration Reset:** Reset the tool to its default configuration.
- **Brute-force Decryption:** Perform brute-force decryption attempts with customizable key lengths.
- **User-Friendly Commands:** Intuitive commands for a smooth user experience.

### Requirements

- Python 3.x
- `arc4` module
- `requests` module

## Installation

Ensure that Python and the required modules are installed:

```bash
pip install arc4 requests
```

## Usage

To start the interactive mode, run the script:

```bash
python rcs.py
```

### Commands

- `relp`: Display usage instructions.
- `rak <new-key>`: Add a new encryption key.
- `rch`: Clear encryption/decryption history.
- `rck`: Display the currently saved encryption keys.
- `rdk -<key_number>`: Delete a specified encryption key.
- `rxit`: Exit the tool.
- `rsh`: Display encryption/decryption history.
- `rc <text>`: Perform a brute-force decryption on the specified text.
- `res`: Reset to default configuration.
- `rcu`: Check for updates.

## Functions

### `print_message(message)`

Prints a message to the console with newline characters before and after the message.

### `get_input(prompt, default=None)`

Prompts the user for input. If no input is provided, returns the default value.

### `load_keys()`

Loads encryption keys from the key file.

### `save_keys()`

Saves encryption keys to the key file.

### `reset()`

Resets the tool to its default configuration by deleting the key and history files and restoring the default key.

### `add_key(new_key)`

Adds a new encryption key if it does not already exist.

### `delete_key(key_number)`

Deletes a specified encryption key by its index number, unless it is the default key.

### `utf16_to_bytes(s)`

Converts a UTF-16 string to bytes.

### `rc4_encrypt(key, plaintext)`

Encrypts plaintext using the RC4 algorithm and the provided key.

### `rc4_decrypt(key, ciphertext)`

Decrypts ciphertext using the RC4 algorithm and the provided key.

### `bytes_to_hex(b)`

Converts bytes to a hexadecimal string.

### `hex_to_bytes(h)`

Converts a hexadecimal string to bytes.

### `choose_key_for_encryption()`

Prompts the user to choose a key for encryption from the available keys.

### `choose_key_for_decryption()`

Displays the available keys and returns them for decryption attempts.

### `save_history(record)`

Saves a record to the history file.

### `display_history()`

Displays the history of encrypted and decrypted messages.

### `clear_history()`

Clears the history of encrypted and decrypted messages.

### `check_for_updates()`

Checks for updates to the tool by querying the update URL.

### `handle_command(user_input)`

Handles user input commands and performs the appropriate actions.

### `interactive_mode()`

Starts the interactive mode for the tool, allowing users to enter commands and encrypt/decrypt text.

### `print_help()`

Prints the usage instructions for the tool.

### `display_keys()`

Displays the currently saved encryption keys.

### `decrypt_text(user_input)`

Decrypts the provided text using the specified key or all available keys.

### `encrypt_text(plaintext)`

Encrypts the provided plaintext using the chosen key and saves the result to the history.

### `bruteforce_decrypt(ciphertext)`

Performs a brute-force decryption attempt on the provided ciphertext using keys of specified lengths.

## Example Usage

### Encrypting Text

1. Enter interactive mode:

   ```bash
   python rcs.py
   ```

2. Provide the text to encrypt:

   ```
   # Hello, World!
   ```

3. Choose a key for encryption or use the default key:

   ```
   # Choose a key number (default is 0): 0
   ```

4. The encrypted text will be displayed and saved to the history.

### Decrypting Text

1. Enter interactive mode:

   ```bash
   python rcs.py
   ```

2. Provide the encrypted text in the format `- <encrypted_text>`:

   ```
   # - 5D41402ABC4B2A76B9719D911017C592
   ```

3. The tool will attempt to decrypt the text using all available keys and display the results.

### Adding a New Key

1. Enter interactive mode:

   ```bash
   python rcs.py
   ```

2. Add a new key:

   ```
   # rcs-adk my-new-key
   ```

### Displaying History

1. Enter interactive mode:

   ```bash
   python rcs.py
   ```

2. Display the history of encrypted and decrypted messages:

   ```
   # rcs-hst
   ```

## Feature Highlights

### Secure Text Encryption and Decryption

The RCS tool uses the RC4 encryption algorithm to securely encrypt and decrypt text. Users can choose from multiple encryption keys to enhance security.

### Easy Key Management

The tool allows users to easily manage their encryption keys. Keys can be added, deleted, and displayed with simple commands.

### History Tracking

All encrypted and decrypted messages are saved in a history file. Users can view and clear the history as needed, ensuring they can track their encryption activities.

### Update Notifications

RCS checks for updates and notifies users when a new version is available. This ensures that users always have access to the latest features and security improvements.

### Configuration Reset

Users can reset the tool to its default configuration, which is useful if they need to start fresh or encounter issues with their current setup.

### Brute-force Decryption

The tool includes a brute-force decryption feature that allows users to attempt decryption with keys of various lengths. This can be useful for recovering encrypted text when the key is unknown.

### User-Friendly Interface

The RCS tool provides a user-friendly interface with intuitive commands, making it easy for users to encrypt and decrypt text, manage keys, and view history without needing advanced technical knowledge.

## Support and feedback

If you have any questions or need help, please contact the development team: `rincynar@gmail.com`
Thank you for using the `rcs` tool software!

## License

RCS is licensed under the MIT License. See the [LICENSE](https://github.com/RinCynar/rcs/blob/main/LICENSE) file for more information.