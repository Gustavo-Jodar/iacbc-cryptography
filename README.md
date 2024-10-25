# IACBC Cipher Algorithm

This project demonstrates the IACBC (Incremental Authenticated Cipher Block Chaining) encryption algorithm using AES. It encrypts and decrypts a text excerpt from Shakespeare, showcasing the algorithm's ability to process and verify data integrity.

### Usage (Functioning of main)

1. **Encrypt a text file**: Encrypts the content of `input.txt` containing a Shakespeare excerpt and saves the encrypted output to `cipher.txt`.
2. **Decrypt the file**: Decrypts `cipher.txt` and verifies integrity, then saves the result to `plain.txt`.


Clone the project

```bash
  git clone https://github.com/Gustavo-Jodar/iacbc-cryptography.git
```

Go to the project directory

```bash
  cd iacbc-cryptography
```

Install dependencies

```bash
  pip3 install pycryptodome
```

Start program

```bash
  python3 iacbc.py
```

### Requirements

This code requires the `pycryptodome` library for AES encryption and PBKDF2 key derivation.

Install it with:
```bash
pip3 install pycryptodome
```
## Authors

- [@Gustavo-Jodar github page](https://github.com/Gustavo-Jodar)

