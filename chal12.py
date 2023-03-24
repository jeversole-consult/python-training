"""
--------------------------------------------------------------------------------------------------
 Challenge 12 - 

 Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key 
(for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is 
that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. 
Discover the block size of the cipher. You know it, but do this step anyway. Detect that the function is using ECB. You 
already know, but do this step anyways. Knowing the block size, craft an input block that is exactly 1 byte short 
(for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that 
last byte position. Make a dictionary of every possible last byte by feeding different strings to the oracle; 
for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation. Match the output of the 
one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.

Reference: https://cryptopals.com/sets/2/challenges/12

Notes:

This one requires some thought to figure exactly what the ask is. The guidance is to stay away from decoding the
unknown string. We already have code to base64 decode that string so why not decode it and look at it. The question here was
to figure out exactly what we are trying to do. When we look at a number of the routines written for the challenges up to 
challenge 12 we have been building components of a simulator. We've written various routines for various specific problems, 
and, they seem to fit into building a general testing tool. 

Further research into the use of the term "Oracle" specific to cryptography has been helpful. An Oracle enables us to 
generate test data for the heavy lifting of testing decryption code that follows specific algorhythms. A black box simulator
comes to mind. This black box lets us pass parameters in and get back encrypted test data for use in testing our code. 
The black box programmed in this case is more of a whit box takes variables for input to meet the requirements of the 
challenge which are to have a constant unknown text, a constant unknown key, an unknown encryption scheme, but the ability 
to provide a known text to an "Oracle" that we can use to find the "constant" unknown text the Oracle is using.

With respect to this challenge the missing link for the programmer was not how to write loops and if statements, 
decode base64, or how to concatenate strings. The question was why? Why do this? Even though the title of the challenge is 
to build a script that performs a single byte ECB attack something is missing. How might this be used in the real world?

A couple of comments on the above question. Further research reveals that providing known text to a black box
that will return the known text encrypted along with unknown text is referred to as a "Chosen-plaintext Attack". 
A search using the string "Chosen-plaintext attack" provides a number of articles on this topic.

Technical:

The experience with this challenge was not too bad figuring out block sizes and lengths. There seems to be more than one
approach, but after spending way too much time trying to figure out byte 17 I decided to take a simpler approach. Just
prepend the length of the unknown string and back down char at a time from there. Seems to work.

For this exercise I chose to implement more of a white box for the oracle. By that I mean I'm passing in the unknown
string and key as arguments and pretending I don't know them. It's a short step away to turn the white box into a 
black box, but not on this exercise.

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re

print('\n --- Challege 12 ---\n')

#
# 1) Initialize a variable with a known plaintext string. 
# 
# 2) Decode the base64 encoded unknown string into a variable.
# 
# 3) Pretend to create a random key and assign it to a variable.
#
# 4) Discover the block size from the oracle and the number of blocks
#
# 5) Use the AES ECB Oracle to encrypt a concatenated string of known + unknown plaintext
# 
# 6) Run it through the ECB decrypt algorithm outlined in the challenge to isolate byte at a time
#    and discover the byte using a brute force search.
#

# Unknown test string base64 encoded. Pretend not to know it
data = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown_bytes = base64.b64decode(data.encode('latin-1'))

known_string = b'A'
# Pretend not to know this key
unknown_key  = b'YELLOW SUBMARINE'
found_str    = b''
attack_block = b''
# 
# 
start_len = len(crypto_funcs.aes_ecb_oracle(unknown_bytes, unknown_key))

while True:
    #
    # When the length of the return byte string changes we can compute the block size based on the change in length of 
    # new crypto string and the original crypto string
    #
    new_len = len(crypto_funcs.aes_ecb_oracle(known_string + unknown_bytes, unknown_key))
    if (new_len > start_len):
        block_size = new_len - start_len
        num_blocks = int(new_len/block_size)
        print("Block size   - ", block_size)
        print("Total blocks - ", num_blocks)
        break
    else:
        known_string += b'A'

offset = len(known_string)

# Declare some vars 
prefix_block = b''
found_bytes   = b''

target_len = num_blocks * block_size

# Tricky sort of loop below. Note the early exit and the numbers it is based on. The approach is to start with
# with a prefix the size of the unknown text itself and back off one char at a time from that. When to stop is 
# the trick.

for j in range((target_len)-1, -1, -1):

    if (len(found_bytes) == (target_len - offset - block_size)):
        # Done
        break
        
    prefix_block = b'A' * j
    cipher_bytes = crypto_funcs.aes_ecb_oracle(prefix_block + unknown_bytes, unknown_key)

    for k in range(256):
    # This is the single byte brute force search for the matching encrypted byte
        new_cipher_bytes = crypto_funcs.aes_ecb_oracle(prefix_block + found_bytes + k.to_bytes(1,'little') + unknown_bytes, unknown_key)

        if (bytes(cipher_bytes)[:(target_len-1)] == bytes(new_cipher_bytes)[:(target_len-1)]):
            # We found a byte match
            found_bytes += k.to_bytes(1,'little')
            # Print out what we've found so far
            print(found_bytes)
            break

# 
