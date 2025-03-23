"""
Ciphers Module

This module contains implementations of various cryptographic ciphers.

Functions:
- (To be implemented): Functions for encryption and decryption using different cipher techniques.

Dependencies:
- numpy: Used for numerical operations and array manipulations, if required by the cipher implementations.
"""

import numpy as np

"""
Caesar's Cipher: A substitution cipher that shifts the letters of the plaintext
by a fixed number of positions in the alphabet.
For example, with a shift of 3, 'A' becomes 'D', 'B' becomes 'E', and so on.
It is one of the simplest and most widely known encryption techniques.
"""


def caesar_encrypt(plaintext, key):
    """
    Encrypts the plaintext using Caesar's cipher.

    Args:
      plaintext (str): The text to be encrypted.
      key (int): The number of positions to shift each letter.

    Returns:
      str: The encrypted text.
    """
    encrypted = []
    for char in plaintext:
        if char.isalpha():
            shift_base = ord("A") if char.isupper() else ord("a")
            encrypted.append(chr((ord(char) - shift_base + key) % 26 + shift_base))
        else:
            encrypted.append(char)
    return "".join(encrypted)


def caesar_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using Caesar's cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      key (int): The number of positions to shift each letter back.

    Returns:
      str: The decrypted text.
    """
    return caesar_encrypt(ciphertext, -key)


"""
Vigenère Cipher: A method of encrypting alphabetic text by using a simple form of polyalphabetic substitution.
It uses a keyword where each letter of the keyword determines the shift for the corresponding letter in the plaintext.
For example, if the keyword is "KEY" and the plaintext is "HELLO", the first letter 'H' is shifted by the position of 'K',
the second letter 'E' by the position of 'E', and so on. The keyword is repeated as necessary to match the length of the plaintext.
"""


def vigenere_encrypt(plaintext, keyword):
    """
    Encrypts the plaintext using the Vigenère cipher.

    Args:
      plaintext (str): The text to be encrypted.
      keyword (str): The keyword used for encryption.

    Returns:
      str: The encrypted text.
    """
    encrypted = []
    keyword = keyword.lower()
    keyword_length = len(keyword)
    keyword_index = 0

    for char in plaintext:
        if char.isalpha():
            shift_base = ord("A") if char.isupper() else ord("a")
            shift = ord(keyword[keyword_index % keyword_length]) - ord("a")
            encrypted.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
            keyword_index += 1
        else:
            encrypted.append(char)
    return "".join(encrypted)


def vigenere_decrypt(ciphertext, keyword):
    """
    Decrypts the ciphertext using the Vigenère cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      keyword (str): The keyword used for decryption.

    Returns:
      str: The decrypted text.
    """
    decrypted = []
    keyword = keyword.lower()
    keyword_length = len(keyword)
    keyword_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift_base = ord("A") if char.isupper() else ord("a")
            shift = ord(keyword[keyword_index % keyword_length]) - ord("a")
            decrypted.append(chr((ord(char) - shift_base - shift) % 26 + shift_base))
            keyword_index += 1
        else:
            decrypted.append(char)
    return "".join(decrypted)


def gcd(a, b):  # For Affine Cipher
    """
    Computes the greatest common divisor of two numbers using the Euclidean algorithm.

    Args:
      a (int): The first number.
      b (int): The second number.

    Returns:
      int: The greatest common divisor of a and b.
    """
    while b:
        a, b = b, a % b
    return a


"""
Affine Cipher: A type of monoalphabetic substitution cipher, where each letter in an alphabet is mapped to its numeric equivalent,
encrypted using a simple mathematical function, and then converted back to a letter. The encryption function is:
E(x) = (a * x + b) % 26
where 'a' and 'b' are keys, and 'x' is the numeric equivalent of the plaintext letter. The decryption function is:
D(x) = a_inv * (x - b) % 26
where 'a_inv' is the modular multiplicative inverse of 'a' modulo 26.

The key 'a' must be chosen such that gcd(a, 26) = 1 to ensure that 'a' has an inverse modulo 26.
"""


def affine_encrypt(plaintext, a, b):
    """
    Encrypts the plaintext using the Affine cipher.

    Args:
      plaintext (str): The text to be encrypted.
      a (int): The multiplicative key (must satisfy gcd(a, 26) = 1).
      b (int): The additive key.

    Returns:
      str: The encrypted text.
    """
    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26.")

    encrypted = []
    for char in plaintext:
        if char.isalpha():
            shift_base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - shift_base
            encrypted.append(chr((a * x + b) % 26 + shift_base))
        else:
            encrypted.append(char)
    return "".join(encrypted)


def affine_decrypt(ciphertext, a, b):
    """
    Decrypts the ciphertext using the Affine cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      a (int): The multiplicative key (must satisfy gcd(a, 26) = 1).
      b (int): The additive key.

    Returns:
      str: The decrypted text.
    """
    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26.")

    a_inv = pow(a, -1, 26)  # Modular multiplicative inverse of 'a' modulo 26
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            shift_base = ord("A") if char.isupper() else ord("a")
            y = ord(char) - shift_base
            decrypted.append(chr((a_inv * (y - b)) % 26 + shift_base))
        else:
            decrypted.append(char)
    return "".join(decrypted)


def matrix_mod_inv(matrix, modulus):  # For Hill Cipher
    """
    Computes the modular inverse of a square matrix under a given modulus.

    Args:
      matrix (numpy.ndarray): A square matrix represented as a numpy array.
      modulus (int): The modulus for the modular arithmetic.

    Returns:
      numpy.ndarray: The modular inverse of the matrix.

    Raises:
      ValueError: If the matrix is not invertible under the given modulus.
    """
    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError("Only square matrices are supported.")

    # Calculate the determinant
    det = int(round(np.linalg.det(matrix))) % modulus

    # Check if the determinant has a modular inverse
    try:
        det_inv = pow(det, -1, modulus)
    except ValueError:
        raise ValueError("Matrix is not invertible under the given modulus.")

    # Compute the adjugate matrix
    adjugate = np.round(np.linalg.inv(matrix) * det).astype(int) % modulus

    # Apply the modular inverse of the determinant and modulus to the adjugate
    inverse = (det_inv * adjugate) % modulus

    return inverse


"""
Hill Cipher: A polygraphic substitution cipher based on linear algebra.
It uses a key matrix to encrypt and decrypt the text by treating the plaintext as a series of vectors.
The encryption function is:
E(P) = K * P mod 26
where 'E(P)' is the encrypted vector, 'K' is the key matrix, and 'P' is the plaintext vector.
The decryption function is:
D(C) = K_inv * C mod 26
where 'D(C)' is the decrypted vector, 'K_inv' is the modular inverse of the key matrix, and 'C' is the ciphertext vector.
"""


def hill_encrypt(plaintext, key_matrix):
    """
    Encrypts the plaintext using the Hill cipher.

    Args:
      plaintext (str): The text to be encrypted.
      key_matrix (numpy.ndarray): The encryption key matrix.

    Returns:
      str: The encrypted text.
    """
    n = key_matrix.shape[0]
    if key_matrix.shape[0] != key_matrix.shape[1]:
        raise ValueError("Key matrix must be square.")

    plaintext = plaintext.lower().replace(" ", "")
    while len(plaintext) % n != 0:
        plaintext += "x"  # Padding with 'x' to fit the matrix size

    plaintext_vectors = [
        [ord(char) - ord("a") for char in plaintext[i : i + n]]
        for i in range(0, len(plaintext), n)
    ]

    encrypted = []
    for vector in plaintext_vectors:
        encrypted_vector = np.dot(key_matrix, vector) % 26
        encrypted.extend(chr(num + ord("a")) for num in encrypted_vector)

    return "".join(encrypted)


def hill_decrypt(ciphertext, key_matrix):
    """
    Decrypts the ciphertext using the Hill cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      key_matrix (numpy.ndarray): The encryption key matrix.

    Returns:
      str: The decrypted text.
    """
    n = key_matrix.shape[0]
    if key_matrix.shape[0] != key_matrix.shape[1]:
        raise ValueError("Key matrix must be square.")

    ciphertext = ciphertext.lower().replace(" ", "")
    ciphertext_vectors = [
        [ord(char) - ord("a") for char in ciphertext[i : i + n]]
        for i in range(0, len(ciphertext), n)
    ]

    key_matrix_inv = matrix_mod_inv(key_matrix, 26)

    decrypted = []
    for vector in ciphertext_vectors:
        decrypted_vector = np.dot(key_matrix_inv, vector) % 26
        decrypted.extend(chr((int(round(num)) % 26) + ord("a")) for num in decrypted_vector)

    return "".join(decrypted)


"""
Substitution Cipher: A method of encryption where each letter in the plaintext is replaced with another letter or symbol.
The key for this cipher is a mapping of each letter in the alphabet to a unique substitution.
"""


def substitution_encrypt(plaintext, key):
    """
    Encrypts the plaintext using a substitution cipher.

    Args:
      plaintext (str): The text to be encrypted.
      key (dict): A dictionary mapping each letter to its substitution.

    Returns:
      str: The encrypted text.
    """
    encrypted = []
    for char in plaintext:
        if char.isalpha():
            if char.isupper():
                encrypted.append(key.get(char, char))
            else:
                encrypted.append(key.get(char.lower(), char).lower())
        else:
            encrypted.append(char)
    return "".join(encrypted)


def substitution_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using a substitution cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      key (dict): A dictionary mapping each letter to its substitution.

    Returns:
      str: The decrypted text.
    """
    reverse_key = {v: k for k, v in key.items()}
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                decrypted.append(reverse_key.get(char, char))
            else:
                decrypted.append(reverse_key.get(char.lower(), char).lower())
        else:
            decrypted.append(char)
    return "".join(decrypted)


"""
OTP Cipher: A symmetric encryption algorithm that generates a random key for each message.
The key must be at least as long as the message and should only be used once.
The encryption function is:
C = P XOR K
where 'C' is the ciphertext, 'P' is the plaintext, and 'K' is the one-time pad key.
The decryption function is:
P = C XOR K
where 'P' is the plaintext, 'C' is the ciphertext, and 'K' is the one-time pad key.
"""


def otp_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the One-Time Pad (OTP) cipher.

    Args:
      plaintext (str): The text to be encrypted.
      key (str): The one-time pad key (must be at least as long as the plaintext).

    Returns:
      str: The encrypted text.
    """
    if len(key) < len(plaintext):
        raise ValueError("Key must be at least as long as the plaintext.")

    encrypted = []
    for p, k in zip(plaintext, key):
        encrypted.append(chr(ord(p) ^ ord(k)))
    return "".join(encrypted)


def otp_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the One-Time Pad (OTP) cipher.

    Args:
      ciphertext (str): The text to be decrypted.
      key (str): The one-time pad key (must be at least as long as the ciphertext).

    Returns:
      str: The decrypted text.
    """
    if len(key) < len(ciphertext):
        raise ValueError("Key must be at least as long as the ciphertext.")

    decrypted = []
    for c, k in zip(ciphertext, key):
        decrypted.append(chr(ord(c) ^ ord(k)))
    return "".join(decrypted)
