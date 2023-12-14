"""
--------------------------------------------------------------------------------------------------
 Challenge 16 - 

 CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, 
split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate
the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?

Reference: https://cryptopals.com/sets/2/challenges/16

Notes:

When I read the above intro I find it one of those that I have to read over and over again to get the connection.
Connecting the previous Challenge 15 to the test strings introduced is a mystery. Also, technical details of
exactly how to escape data in a string to meet the specs for this exercise leaves me to scratch my head. I can clearly
use this exercise to fill in yet some more gaps in my understanding of the subject matter.

After researching this exercise there are a number of points that help me breaking it down from the top:

1) The end goal is to forge a token that escalates privilege to admin, a.k.a. an admin token. This means that understanding
a bit about how common tokens are architected in plaintext plays a role and we can see that in the description of the 
challenge.

2) Understanding why special characters are escaped in this challenge was tricky for me. It's there to make the challenge
less than trivial, and rightly so as to grasp how to exploit tokens that are generated using a general pattern that is 
known to be used by applications. 

3) In this use case we have a header, user supplied data (body), and footer that are used to generate a token. The 
attacker has control of the body. Given the header/body/footer pattern we can look at how to use this knowledge to forge a 
new token that escalates privilege.

4) What we need is a cypher text that decrypts to have the string "admin=true;" embedded. To revisit we can't just 
submit that string "as-is" for it will be "escaped" by the app and decryption of the token will return the escaped
characters. Can't get the string back "as-is" embedded in the decrypted sting without some tinkering.

5) The break through for me here was to grasp the use of a known string to return an encrypted string that we know
the block boundaries and can identify the first encrypted block of the user data. Since we know the plain text of this
block we can tinker with the cipher text block using certain XOR operations to get our string into the decrypted text.
Pretty slick...

6) The code below does not attempt to hide key and IV generation. These two values could be buried in closures in routine
or in an object structure and maybe in the future. The objective here is to understand the basic vulnerability.

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re
import time
import secrets

print('\n --- Challege 16 ---\n')

# Initialize some variables

blk_len = 16
header = b'comment1=cooking%20MCs;userdata='
body1  = b';admin=true;'
key    = secrets.token_bytes(blk_len)
footer = b';comment2=%20like%20a%20pound%20of%20bacon'

# Construct and pad the plain text. May not be the prettiest way to do it.

plain_txt = crypto_funcs.c16f1_preappend(header, body1, footer)
# Manually pad the txt and print for examination
plain_txt = plain_txt + crypto_funcs.PKCS7_pad(plain_txt, blk_len)
print('Plain Text Padded:\n\n', plain_txt, '\n')

# Generate an IV
IV = secrets.token_bytes(blk_len)
cipher_txt_hex = bytes(crypto_funcs.aes_cbc_mode_encrypt(plain_txt, key, IV)).hex()
cipher_txt_bytes = crypto_funcs.aes_cbc_mode_encrypt(plain_txt, key, IV)

print('\n -- Testing --\n')
print('Cipher Text:\n\n', cipher_txt_bytes, '\n')

# Decrypt and verify just to be sure 

plain_txt2 = crypto_funcs.aes_cbc_mode_decrypt(cipher_txt_bytes, key, IV)

print('Decrypted Text:\n\n', plain_txt2, '\n')

if (body1 in plain_txt2):
    print(body1, " - Found")
else:
    print(body1, " - Not Found")

print('\n -- End Testing --\n')

''' -- END TESTING '''

# Set up some variables
attack_mask =  b'AAAA' + body1
flip_mask    = b'Z' * 16 
attack_bytes = b'Z' * 32 


# Build out the first round with the attack_bytes and encrypt 
plain_txt = crypto_funcs.c16f1_preappend(header, attack_bytes, footer)
# Pad and examine
plain_txt = plain_txt + crypto_funcs.PKCS7_pad(plain_txt, blk_len)
plainlist = [plain_txt[i:i+blk_len] for i in range(0, len(plain_txt), blk_len)]
print('Plain text with two blocks of user data:')
print(*plainlist, sep="\n")

''' -- ENCRYPT -- '''
cipher_txt_bytes = crypto_funcs.aes_cbc_mode_encrypt(plain_txt, key, IV)

# Split the cipher text into blocks so that we can tinker with the 3rd block

blist = [cipher_txt_bytes[i:i+blk_len] for i in range(0, len(cipher_txt_bytes), blk_len)]

# Reassemble, decrypt and see what we get

cipher_txt_bytes = b'' . join(blist)
print("\nCipher text bytes:")
print(*blist, sep="\n")

'''  -- DECRYPT -- '''

plain_txt2 = crypto_funcs.aes_cbc_mode_decrypt(cipher_txt_bytes, key, IV)

# Flip some bits in block 3
flip1 = bytes(a ^ b for a, b in zip(flip_mask, attack_mask))
flip2 = bytes(a ^ b for a, b in zip(flip1, blist[2]))
blist[2] = flip2

# Reassemble and decrypt

cipher_txt_bytes = b'' . join(blist)

'''  -- DECRYPT -- '''
plain_txt2 = crypto_funcs.aes_cbc_mode_decrypt(cipher_txt_bytes, key, IV)
plainlist = [plain_txt2[i:i+blk_len] for i in range(0, len(plain_txt2), blk_len)]
print("\nPlain text bytes after last decrypt: ")
print(*plainlist, sep="\n")

if (body1 in plain_txt2):
    print("\n", body1, " - Found\n")
else:
    print("\n", body1, " - Not Found\n")

print('\n --- End Challege 16 ---\n')