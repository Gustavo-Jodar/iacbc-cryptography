'''

This code was developed by Gustavo Jodar Soares for ASI331 ENSTA's course.
It developes the IACBC cipher algorithm

'''
from Crypto.Protocol.KDF import PBKDF2 # type: ignore
from Crypto.Hash import SHA1 # type: ignore
from Crypto.Cipher import AES # type: ignore


KEY_SIZE = 32
BLOCK_SIZE = 16 #in bytes

def xor_block(b1, b2):
    '''
    xor_blocs: Implements XOR function between two blocks of size BLOCK_SIZE
    inputs: b1, b2 -> <class bytes> blocks of size BLOCK_SIZE
    output: b1 ^ b2 (b1 XOR b2)
    '''
    return bytes(a ^ b for a, b in zip(b1, b2))

def incr_block(block: bytes) -> bytes:
    '''
    incr_block: Increments a block by one (big-endian integer)
    input: block -> <class bytes>
    output: incremented block -> <class bytes>
    '''
    # converting to <class int> to increment
    n = int.from_bytes(block, byteorder='big')
    
    return (n + 1).to_bytes(len(block), byteorder='big')

def pad(block: bytes) -> bytes:
    '''
    pad: Adds PKCS#7 padding to a block
    input: block -> <class bytes>
    output: padded block -> <class bytes>
    '''
    # checking for how much pad is needed, and adding later
    padding_len = BLOCK_SIZE - len(block)
    padding = bytes([padding_len] * padding_len)
    
    return block + padding

def unpad(block: bytes) -> bytes:
    '''
    unpad: Removes PKCS#7 padding from a block
    input: block -> <class bytes>
    output: unpadded block -> <class bytes>
    '''
    # checking number written in the pad and subtracting from the block
    return block[:(BLOCK_SIZE - int(block[-1]))]

def gen_key(pwd: bytes, IV: bytes):
    '''
    gen_key: Generates three keys for encryption using PBKDF2
    inputs: pwd, IV -> <class bytes>
    output: K1, K2, R -> <class bytes>
    '''
    # derives the key -> [K1, K2, R] -> [32,32,16 bytes]
    derived_key = PBKDF2(pwd, IV, dkLen=80, count=10000, hmac_hash_module=SHA1)
    
    K1 = derived_key[:KEY_SIZE]
    K2 = derived_key[KEY_SIZE:(KEY_SIZE*2)]
    R = derived_key[(KEY_SIZE*2):]
    
    return K1, K2, R

def encrypt_block(block: bytes, key: bytes) -> bytes:
    '''
    encrypt_block: Encrypts a block using AES in ECB mode
    inputs: block, key -> <class bytes>
    output: encrypted block -> <class bytes>
    '''
    # AES encryption using Cripto Library
    cipher = AES.new(key, AES.MODE_ECB)
    
    return cipher.encrypt(block)

def decrypt_block(encrypted_block: bytes, key: bytes) -> bytes:
    '''
    decrypt_block: Decrypts a block using AES in ECB mode
    inputs: encrypted_block, key -> <class bytes>
    output: decrypted block -> <class bytes>
    '''
    # AES decryption using Cripto Library
    cipher = AES.new(key, AES.MODE_ECB)
    
    return cipher.decrypt(encrypted_block)

def create_blocks(m: bytes):
    '''
    create_blocks: Splits a message into blocks of size BLOCK_SIZE, adds padding if needed
    input: m -> <class bytes>
    output: list of blocks -> <class bytes>
    '''
    # dividing the message by blocks with size BLOCK_SIZE
    blocks = [m[i:i+BLOCK_SIZE] for i in range(0, len(m), BLOCK_SIZE)]
    
    # in case where the is no block, a full padding block must be added
    if(len(blocks) == 0 ):
        padding_block = bytes([BLOCK_SIZE] * BLOCK_SIZE)
        blocks.append(padding_block)
    
    # in case where the bloc is smaller than BLOCK_SIZE, add the remaining bytes as padding
    elif(len(blocks[-1]) < BLOCK_SIZE):
        blocks[-1] = pad(blocks[-1])       
    
    # in case where the last block fits in BLOCK_SIZE, add a full padding block
    else:
        padding_block = bytes([BLOCK_SIZE] * BLOCK_SIZE)
        blocks.append(padding_block)
    
    return blocks

def extract_blocks(c: bytes):
    '''
    extract_blocks: Splits a ciphertext into blocks of size BLOCK_SIZE
    input: c -> <class bytes>
    output: list of blocks -> <class bytes>
    '''
    # dividing the ciphertext by blocks with size BLOCK_SIZE
    return [c[i:i+BLOCK_SIZE] for i in range(0, len(c), BLOCK_SIZE)]

def encrypt_iacbc(K1: bytes, K2: bytes, R: bytes, m: bytes):
    '''
    encrypt_iacbc: Encrypts a message using IACBC mode
    inputs: K1, K2, R -> <class bytes>, m -> <class bytes>
    output: encrypted message -> <class bytes>
    '''
    # dividing in blocks
    blocks = create_blocks(m)
    num_blocks = len(blocks)
    
    # Calculating the s of the algorithm
    s = []
    aux_R = R
    for i in range(0, num_blocks+1):
        aux_R = incr_block(aux_R)
        s.append(encrypt_block(aux_R, K2))        
    
    
    # Calculating the ciphertext c
    # E stores the list of all ciphertexts c[i] before the xor with s[i] -> the value is used to encrypt the next block
    c = []
    E = []
    c.append(encrypt_block(R, K1))
    E.append(encrypt_block(R, K1))
    for i in range(1, num_blocks+1):
        E.append(encrypt_block(xor_block(blocks[i-1], E[i-1]),K1))
        c.append(xor_block(E[i], s[i]))
    
    # Calulating P_i (xor of all plain texts) used to craft c_m (Authentication block)
    P_i = 0
    if(num_blocks == 1):
        P_i = blocks[0]
    else:
        for i in range(1, num_blocks):
            P_i = xor_block(blocks[i-1], blocks[i])
    
    # Authentication block
    c_m = xor_block(s[0], encrypt_block(xor_block(P_i, E[-1]),K1))
    c.append(c_m)
    
    return b''.join(c)

def decrypt_iacbc(K1: bytes, K2: bytes, R: bytes, c: bytes):
    '''
    decrypt_iacbc: Decrypts a message encrypted with IACBC mode
    inputs: K1, K2, R -> <class bytes>, c -> <class bytes>
    output: decrypted message -> <class bytes>
    '''
    # dividing in blocks
    blocks = extract_blocks(c)
    num_blocks = len(blocks)
    
    # Calculating the s of the algorithm
    s = []
    aux_R = R
    for i in range(0, num_blocks+1):
        aux_R = incr_block(aux_R)
        s.append(encrypt_block(aux_R,K2))        
    
    # Calculating the Plain text P
    # E stores the list of all ciphertexts c[i] xor(ed) with s[i] -> the value is used to decrypt the next block
    E = []
    P = []
    E.append(blocks[0])
    for i in range(1,num_blocks-1):
        E.append(xor_block(s[i], blocks[i]))
        P.append(xor_block(decrypt_block(E[i], K1), E[i-1]))
    
    # Calulating P_i (xor of all plain texts) used to craft c_m (Authentication block)
    P_i = 0
    if(len(P) == 1):
        P_i = P[0]
    else:
        for i in range(1, len(P)):
            P_i = xor_block(P[i-1], P[i])
    
    # Comparing P_i with the authentication block
    authentication_block = xor_block(decrypt_block(xor_block(blocks[-1], s[0]), K1), E[-1])
    
    if(P_i == authentication_block):
        print("----> Decryption authenticated !")
        # Unpadding last block if authentication is a success
        P[-1] = unpad(P[-1])
        
    else:
        print("----> Authentication FAILED - The message was compromised")
    
    return b''.join(P)

def encrypt(pwd: bytes, IV: bytes, m: bytes):
    '''
    encrypt: Encrypts a message using a password and initialization vector
    inputs: pwd, IV, m -> <class bytes>
    output: encrypted message -> <class bytes>
    '''
    K1, K2, R = gen_key(pwd, IV)
    
    return encrypt_iacbc(K1, K2, R, m)

def decrypt(pwd: bytes, IV: bytes, c: bytes):
    '''
    decrypt: Decrypts a message using a password and initialization vector
    inputs: pwd, IV, c -> <class bytes>
    output: decrypted message -> <class bytes>
    '''
    K1, K2, R = gen_key(pwd, IV)
    
    return decrypt_iacbc(K1, K2, R, c)

def run(params):
    '''
    run: Reads a file, encrypts or decrypts its content, writes the output
    input: params -> <class dict> contains parameters for encryption/decryption
    output: encrypted/decrypted file
    '''
    with open(params['input'], "rb") as file:
    
        content = file.read()
    
        if(params['enc']):
            print(f"\n----> Encrypting text from {params['input']}...\n")
            output = encrypt(params['pwd'], params['IV'], content)
            print(f"Text encrypted, it is stored in {params['out']}\n")
            
        else:
            print(f"\n----> Decrypting text from {params['input']}...\n")
            output = decrypt(params['pwd'], params['IV'], content)
            print(f"\nText decrypted, it is stored in {params['out']}")
        
        with open(params['out'], "wb") as file:
            file.write(output)

def main():
    
    params1 = {
        "enc": True, 
        "pwd": "Password",
        "IV": "IV",
        "input": "input.txt",
        "out": "cipher.txt"
    }
    params2 = {
        "enc": False, 
        "pwd": "Password",
        "IV": "IV",
        "input": "cipher.txt",
        "out": "plain.txt"
    }
    
    run(params1)
    run(params2)


if __name__ == "__main__":
    main()