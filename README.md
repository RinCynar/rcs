# rcs 1.52 - RC4-based text encryption tool

Welcome to the official website of `rcs` tool software! `rcs` is a powerful text encryption tool based on the RC4 encryption algorithm, with a simple design and easy to use. Whether you need to protect sensitive information or are interested in encryption technology, `rcs` is your ideal choice.

## Latest version: 1.52

### Features

- **Multi-key management**:
- Supports adding, deleting, resetting and displaying encryption keys.
- Default key configuration to ensure convenience for first-time use.

- **Efficient encryption and decryption**:
- Text encryption and decryption based on the RC4 algorithm.
- Supports multiple encoding formats to ensure data integrity and security.

- **History management**:
- Automatically save the history of each encryption/decryption operation.
- Supports displaying and clearing history for easy management and reference.

- **Check for update function**:
- One-click check for the latest version information to ensure that you are using the latest and safest version.

- **Interactive command line interface**:
- Simple and intuitive user interface, supports multiple command operations, convenient and fast.

### Installation and operation

#### Prerequisites

Please make sure your system has the following software installed:
- Python 3.x
- `requests` library
- `arc4` library

You can use the following commands to install the required libraries:

```sh
pip install requests arc4
```

#### Download and run

1. Download the `rcs` tool software:
[Download link](http://rcva.san.tc/assets/rcs.zip)

2. Unzip the downloaded file and enter the unzipped directory.

3. Run the following command to start the `rcs` tool:

```sh
python rcs.py
```

#### Usage

After entering the interactive mode, you can use the following commands:

- **Encrypt text**:
- Enter the text to be encrypted and press `Enter`, `rcs` will automatically encrypt with the default key.
- You can also select a specific key to encrypt.

- **Decrypt text**:
- Enter `- <ciphertext>` and press `Enter`, `rcs` will try all saved keys for decryption.
- Enter `- <ciphertext> -<key number>` and press `Enter`, `rcs` will use the specified key for decryption.

- **Manage keys**:
- `rcs-adk <new key>`: Add a new key.
- `rcs-dek -<key number>`: Delete the specified key.
- `rcs-cuk`: Display the currently saved keys.
- `rcs-res`: Reset to default key configuration.

- **History**:
- `rcs-hst`: Show history.
- `rcs-cle`: Clear history.

- **Check for updates**:
- `rcs-udt`: Check for new versions.

- **Exit**:
- `rcs-exi`: Exit interactive mode.

- **Help information**:
- `rcs-help`: Display detailed usage help information.

### Examples

```sh
# Start rcs
$ python rcs.py

# Encrypted text
# Hello, World!
Encrypted text: 6A97B9D1A7C6F3E8D...

# Decrypted text
# - 6A97B9D1A7C6F3E8D...
Decrypted text: Hello, World!

# Add a new key
# rcs-adk MyNewKey
Key added: MyNewKey

# Check for updates
# rcs-udt
This version is 1.52.
Connecting to rcva.san.tc
Latest version: 1.52
```

### Support and feedback

If you have any questions or need help, please contact the development team: `rincynar@gmail.com`

Thank you for using the `rcs` tool software!