"""
--------------------------------------------------------------------------------------------------
 Challenge 15 - 

PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.

Cryptography Services | NCC Group

Notes:

To meet the spec on this challenge a new routine was added to crypto_funcs - PKCS7_padchk. It makes good sense to 
exercise python constructs like try except so decided to use it in the new method.

Technical:

No much going on for this one except how to slice and dice python byte strings.

--------------------------------------------------------------------------------------------------

"""
import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re
import time

print('\n --- Challege 15 ---\n')

# This script is trivial at the call level since the work is going to be done in the new routine in
# crypto_funcs, PCKS7_padchk

blocksize = 16

teststr = b'ICE ICE BABY\x04\x04\x04\x04'
print('teststr = ', teststr)
crypto_funcs.PKCS7_padchk(teststr, blocksize)

print("\n")
teststr = b'ICE ICE BABY\x05\x05\x05\x05'
print('teststr = ', teststr)
crypto_funcs.PKCS7_padchk(teststr, blocksize)

print("\n")
teststr = b'ICE ICE BABY\x01\x02\x03\x04'
print('teststr = ', teststr)
crypto_funcs.PKCS7_padchk(teststr, blocksize)

print('\n --- End Challege 15 ---\n')


# End chal14