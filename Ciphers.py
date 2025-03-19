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
      shift_base = ord('A') if char.isupper() else ord('a')
      encrypted.append(chr((ord(char) - shift_base + key) % 26 + shift_base))
    else:
      encrypted.append(char)
  return ''.join(encrypted)

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
      shift_base = ord('A') if char.isupper() else ord('a')
      shift = ord(keyword[keyword_index % keyword_length]) - ord('a')
      encrypted.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
      keyword_index += 1
    else:
      encrypted.append(char)
  return ''.join(encrypted)

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
      shift_base = ord('A') if char.isupper() else ord('a')
      shift = ord(keyword[keyword_index % keyword_length]) - ord('a')
      decrypted.append(chr((ord(char) - shift_base - shift) % 26 + shift_base))
      keyword_index += 1
    else:
      decrypted.append(char)
  return ''.join(decrypted)


def gcd(a, b): #For Affine Cipher
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
      shift_base = ord('A') if char.isupper() else ord('a')
      x = ord(char) - shift_base
      encrypted.append(chr((a * x + b) % 26 + shift_base))
    else:
      encrypted.append(char)
  return ''.join(encrypted)

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
      shift_base = ord('A') if char.isupper() else ord('a')
      y = ord(char) - shift_base
      decrypted.append(chr((a_inv * (y - b)) % 26 + shift_base))
    else:
      decrypted.append(char)
  return ''.join(decrypted)
