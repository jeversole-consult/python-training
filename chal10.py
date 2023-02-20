"""
--------------------------------------------------------------------------------------------------
 Challenge 10 - Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the 
fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the
cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a 
"fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead 
of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function 
from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV 
of all ASCII 0 (\x00\x00\x00 &c)

Reference: https://cryptopals.com/sets/2/challenges/10

Notes:

1) Some of the instructions above are a bit confusing. To sort that out further research on CBC was
in order. For example, the term "added" used above. The equations for CBC call for an XOR and it
turns out that XOR shares many properties with binary addition. For those just getting started 
it is good to dive into that detail where the use of these terms are very subtle and specific for
the particular problem. It is good to know the specific use of the term so as not to confuse it
with something you might find intuitive.

2) &c above means Et cetra. In this case we will start with a 16 byte IV of all zeros.

3) The instructions suggest using the ECB function written before. In the solutions here that
is near trivial from a coding perspective. Swap out some parameters and you're done.

4) Considerable time was spent studying CBC and how it works. While previous code was written 
involving logic and loops to detect an ECB encrypted line in a file (Challenge 8), the code
below uses only the pycryptodomes library to get the AES job done. It is as simple, if not simpler,
than using the command line with OpenSSL.

5) Much was learned about CBC

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES

print('\n --- Challege 10 ---\n')

# Initialize some variables
#

IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
key = b'YELLOW SUBMARINE'

#
# The file is base64 encoded.
#
# 1) Read the file in as one big string. 
# 
# 2) The key and IV are initialized/hardcoded above
#
# 3) Create a new AES object using CBC mode supplying the key and IV
# 
# 4) Call the decrypt method against the the byte string read in from the file
# 
# 5) Print result and see what we got.
#

b64_file = open("chal10_input.txt", "r")
data = b64_file.read()

message_bytes = base64.b64decode(data.encode('latin-1'))

cipher = AES.new(key, AES.MODE_CBC,IV)

print("The decrypted text is printed below\n-----------------------------------\n")
print(cipher.decrypt(message_bytes).decode('latin-1'))

