"""
--------------------------------------------------------------------------------------------------
 Challenge 7 - AES in ECB mode

 The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
 
"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because 
it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get 
ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
 

 -- Notes:

 First approach here is to use the pycryptodomes library. This library is a fork off the defunct
 pycrypto library. Looks like it works.
--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES

print('\n --- Challege 7 ---\n')

#
# The file is base64 encoded at the byte level. The approach is as follows:
#
# 1) Read the file in as one big string. 
# 
# 2) Setup the hard coded key
#
# 3) Create a new AES object with ECB mode and call the decrypt method with the key and the 
#    byte encoded data from the file.
#
# 4) Print result and see what we got.
#

b64_file = open("chal7_input.txt", "r")
data = b64_file.read()

message_bytes = base64.b64decode(data.encode('latin-1'))

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)

print("The decrypted text is printed below\n-----------------------------------\n")
print(cipher.decrypt(message_bytes).decode('latin-1'))
