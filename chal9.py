"""
--------------------------------------------------------------------------------------------------
 Challenge 9 - Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. 
But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an 
even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the 
end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"

Notes:

1) This is another byte oriented task. All the code we have written before that deals with strings
   and bytes is a guide on how to do this one.
2) This is a good opportunity to look at PKCS#7: 

https://en.wikipedia.org/wiki/Padding_(cryptography)#:~:text=PKCS%237%20is%20described%20in,message%20needs%20to%20be%20extended.

--------------------------------------------------------------------------------------------------
"""

import pdb
import crypto_funcs

print('\n --- Challege 9 ---\n')

#
# The approach here is to have a block size in a variable and test the input for its length. When
# padding arbitrary length trailer blocks the value of the padding byte is dependent on the number
# of bytes needed to complete the block based on the block length. In this specific problem the 
# block length # is 20 bytes. The input is 16 bytes and requires 4 bytes to make 20. PKCS#7 says 
# we need 4 bytes to pad this block and use a binary number 4 as the byte value of each pad byte. 
# If it # were 5 bytes we would use a binary 5 as the value for each padding byte.
# 
# The code below is written to be relative to the block size which is hardcoded here, but expected
# to be auto determined for any future production code.
#
block_size = 20
trailer_block = b'YELLOW SUBMARINE'
padnum = block_size - len(trailer_block)
for i in range(0,padnum):
    trailer_block += padnum.to_bytes(1,'little')

# Not sure about a space being in front of the next line for some reason. Something to 
# checkout.

print('Pad Number: ', padnum, '\n\n', 'Trailer block: ',trailer_block)
