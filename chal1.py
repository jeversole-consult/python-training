"""
--------------------------------------------------------------------------------------------------
 Challenge 1 - Convert hex to base64

 The string:
 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 Should produce:

 SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

 -- Notes:

 - The Set 1 Challanges begin with a encoding and decoding exercise. 
 - Understanding encoding, decoding, translating, etc. are essential to this problem space
 - There are python utilities available to encode and decode 
 - Be diligent in the study of "one liners". The heavy lifter in this challenge is accomplished
   using the following "one-liner":

     b64 = b64encode(bytes.fromhex(hex)).decode()
--------------------------------------------------------------------------------------------------
"""
import codecs
from base64 import b64encode, b64decode

#
# Print the challenge number
#
print('\n--- Challege 1 ---\n')

#
# Initialize the string with the hex value provided by the exercise then use python routines 
# to do the conversion. 
#
hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64 = b64encode(bytes.fromhex(hex)).decode()

print('Hex value: ', hex)
print('\nbase64 equivalent:', b64)



