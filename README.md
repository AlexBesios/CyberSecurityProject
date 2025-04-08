# Message Encryptor/Decryptor

This is a GUI-based application for encrypting and decrypting messages using various cryptographic ciphers. The application provides an easy-to-use interface for selecting a cipher, performing encryption or decryption, and viewing the results.

## Features

- **Caesar Cipher**: A substitution cipher that shifts letters by a fixed number of positions.
- **Vigenère Cipher**: A polyalphabetic substitution cipher using a keyword.
- **Affine Cipher**: A monoalphabetic substitution cipher with a mathematical function.
- **Hill Cipher**: A polygraphic substitution cipher based on linear algebra.
- **Substitution Cipher**: A cipher that replaces each letter with a unique substitution.
- **One-Time Pad (OTP)**: A symmetric encryption algorithm using a random key.

## Installation

### Prerequisites

Ensure you have Python 3.8 or higher installed on your system. You will also need the following Python modules:

- `tkinter`: For creating the graphical user interface (GUI).
- `ttkthemes`: For themed widgets in the GUI.
- `numpy`: For numerical operations (used in the Hill cipher).

You can install the required modules using `pip`:

```bash
pip install ttkthemes numpy
```

### Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/your-repo/CyberSecurityProject.git
cd CyberSecurityProject
```

## Usage

1. Run the application:

   ```bash
   python App.py
   ```

2. Use the GUI to:
   - Select a cipher from the dropdown menu.
   - Choose whether to encrypt or decrypt a message.
   - Enter the message and the key.
   - Click the "Perform" button to see the result.

### Key Format for Ciphers

- **Caesar Cipher**: Enter an integer (e.g., `3`).
- **Vigenère Cipher**: Enter a keyword (e.g., `KEY`).
- **Affine Cipher**: Enter two integers separated by a comma (e.g., `5,8`).
- **Hill Cipher**: Enter a square matrix in Python list format (e.g., `[[6, 24], [1, 13]]`).
- **Substitution Cipher**: Enter a dictionary mapping letters (e.g., `{'a': 'm', 'b': 'n', ...}`).
- **One-Time Pad (OTP)**: Enter a string key at least as long as the message.

## Example

### Caesar Cipher

- **Message**: `HELLO`
- **Key**: `3`
- **Action**: Encrypt
- **Result**: `KHOOR`

### Vigenère Cipher

- **Message**: `HELLO`
- **Key**: `KEY`
- **Action**: Encrypt
- **Result**: `RIJVS`

## File Structure

- `App.py`: The main application file containing the GUI logic.
- `Ciphers.py`: Contains the implementation of various cryptographic ciphers.
- `README.md`: Documentation for the project.

- *Made by PhyniX and AlexBesios*
