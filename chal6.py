"""
--------------------------------------------------------------------------------------------------
 Challenge 6 - Break repeating-key XOR
 
 It is officially on, now.
 This challenge isn't conceptually hard, but it involves actual error-prone coding. The other 
 challenges in this set are there to bring you up to speed. This one is there to qualify you. 
 If you can do this one, you're probably just fine up to Set 6.

 There's a file here(chal6_input.txt). It's been base64'd after being encrypted with 
 repeating-key XOR.

 Decrypt it.

 Here's how:

 Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
 Write a function to compute the edit distance/Hamming distance between two strings. 
 The Hamming distance is just the number of differing bits. The distance between:
 this is a test
 and
 wokka wokka!!!

 is 37. Make sure your code agrees before you proceed.

 For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

 The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed 
 perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average 
 the distances. Now that you probably know the KEYSIZE: break the ciphertext into blocks of 
 KEYSIZE length.

 Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
 Solve each block as if it was single-character XOR. You already have code to do this.
 For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
 This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
 
 No, that's not a mistake.
 We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

 -- Notes:

 Thoughts on tackling this problem lead in the direction of first recognizing that a multibyte XOR
 encrypted string is actually composed of multiple substrings that are single byte XOR encrypted.
 That's why if you can figure out the length of the key you break down the larger string into its
 single byte XOR strings and crack those like we did in Challenge 3. A lot of python mechnics to
 pull substrings and iterate across them, but the concept as mentioned in the problem statement
 is straight forward.
 
 A little tricky, but not too bad. We can reuse code already written to accomplish the task and
 for those new to python pay attention to the "one-liners" where variables can be implicit, but
 methods are available based on the return type of a method call. The following example
 shows invocation of a method directly from the returned result of a method in a python import
 file. It also shows the unary operator += that is supported in python. 

    plain_text += crypto_funcs.multi_byte_xor(block, mbkey).decode('ascii')

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs

print('\n --- Challege 6 ---\n')

#
# Read the file into one big variable. The file is base64 encoded at the byte level. We can 
# translate base64 to byte stings. We know that the bytes are encrypted with a multi-byte xor 
# cipher. What we don't know is the length of key, i.e. number of bytes in the key. Our first 
# task is to get a best guess on the rotating byte xor key length. The way to do that is 
# systematically slice and dice the strings, compute the normalized HD for all key lengths and
# look for the minimum. We will run this computation according recommendations from the 
# Challenge 6 page for key lengths 2 through 40.
#

b64_file = open("chal6_input.txt", "r")
data = b64_file.read()

base64_bytes = data.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
#
# The question here is message_bytes in the right format. The answer ends up being yes.
#
# Step 1 - Find best key size
#
# Now that we have data from the challenge 6 file in one long byte string/array we can operate
# on the file using an algorithm to systematically compute Hamming distance averages for each
# key size. 
#
min_AHD, keylen = None, None

for n in range(2,40):
    bytelists = [(message_bytes[i:i+n]) for i in range(0, len(message_bytes)-1, n)]
    lcnt = 0
    k = 0
    # Note: len(bytelists) is the number of lists that you have after you split the mama byte
    # string.
    for j in range(0, len(bytelists)):
        if (j < len(bytelists)-1):
           k = k + crypto_funcs.hamming_dist(bytelists[j],bytelists[j+1])
    k = k/(len(bytelists)-1)
    if ((min_AHD is None) or (k < min_AHD)):
        min_AHD = k
        keylen = n
#
# Getting these numbers right is very tedious, but required to solve the problem
# 
q, ekey, min_fq, mbkey = None,None,None,b''

# Build out the multibyte XOR key by deciphering the set of substrings that have a common
# single byte encryption. Knowing the key length enables us to do this.
#
for m in range(0, keylen):
    s = message_bytes[m:len(message_bytes):keylen]
    #
    # Run single byte XOR decipher on the substring
    #
    q, ekey, min_fq = crypto_funcs.sbx_decipher(s)
    # Append returned key to the multi-byte key string.
    mbkey += ekey.to_bytes(1,'little')

# Use the multibyte key assembled above to XOR with key length blocks from the encrypted string  
# and see what we get. Need to do it block at a time based on key length. Remember how XOR works 
# to return the plain text from encrypted text with a simple XOR of the original key.
# This will decrypt each block with the single byte key for that block.
#
plain_text = ''
blocks = [message_bytes[i:i+keylen] for i in range(0, len(message_bytes), keylen)]
for block in blocks:
    # Decrypt by using the multi-byte XOR and reassemble the plain text
    plain_text += crypto_funcs.multi_byte_xor(block, mbkey).decode('ascii')

# Print the plain text we just assembled with the above loop
#
print("The decrypted text is printed below\n-----------------------------------\n")
print(plain_text)
