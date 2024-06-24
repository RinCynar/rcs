# RCS - Text encryption and decryption tool

## Introduction

RCS is a text encryption and decryption tool developed based on the RC4 encryption algorithm. It is designed to provide users with a simple and powerful encryption solution, supporting multiple key management methods and efficient decryption functions, and is equipped with a powerful brute force cracking tool for decrypting unknown ciphertext.

## Main functions and features

### Encryption and decryption operations

RCS provides an intuitive command line interface and supports the following core functions:

- **Encryption**: Users can choose to use the default key or a custom key to encrypt the input text. The encryption process is based on the RC4 algorithm, which can quickly and efficiently encrypt text data and protect the user's privacy information.

- **Decryption**: Users can decrypt the encrypted text by providing the correct key. The tool supports multiple alternative keys to help users successfully decrypt data in different scenarios.

### Key Management and Configuration

RCS allows users to flexibly manage the keys used in the encryption process:

- **Add Key**: Users can use the command `rcs-adk <new-key>` to add new encryption keys, expand encryption options, and improve security.

- **Delete Key**: Supports deleting the specified encryption key through the command `rcs-dek -<key_number>`. The default key cannot be deleted to ensure system stability.

- **Reset Configuration**: Users can select the command `rcs-res` to restore the default configuration, clear all customized encryption keys, and return the system to its initial state.

### Brute Force Cracking Function

RCS provides a powerful brute force cracking tool for trying to decrypt unknown ciphertext. This function allows users to specify the key length range, and the system will try all possible key combinations until the correct decryption key is found. This provides an effective solution for users to solve the problem of forgetting the key or encountering encrypted text that cannot be decrypted.

### Instructions and command list

RCS has designed a simple and feature-rich command line interface to help users easily complete encryption and decryption operations:

- `rcs-help`: Displays the tool's instructions and command list to help users get started quickly.

- `rcs-adk <new-key>`: Adds a new encryption key to expand encryption options.

- `rcs-dek -<key_number>`: Deletes the specified encryption key to enhance key management capabilities.

- `rcs-res`: Resets all configurations and restores the default encryption key settings.

- `rcs-cuk`: Displays all currently saved encryption keys to help users understand the current system configuration.

- `rcs-pod <text>`: Starts the brute force cracking function and attempts to decrypt the specified ciphertext, which is suitable for solving the situation where the key is forgotten or cannot be decrypted.

### Technical details and implementation

RCS is developed using the Python programming language and implements the RC4 encryption algorithm using the third-party library ARC4. It is compatible with multiple operating systems, including Windows, Mac, and Linux. It uses UTF-16BE encoding to process text data to ensure compatibility and stability on different platforms.

### Next steps

We are committed to continuously optimizing RCS to improve its security, stability, and user experience. In the future, we plan to introduce more advanced encryption algorithms and customized functions to meet the diverse needs of different users for data security.
