"""
--------------------------------------------------------------------------------------------------
 Challenge 8 - Detect AES in ECB mode

In the file chal8_input.txt are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Reference: https://cryptopals.com/sets/1/challenges/8

 -- Notes:

 Approach:
 
 1) Read up on what ECB is so that we have half a clue before we look for existing solutions. 
 2) Search the net for existing solution and adapt them to save time

 Further Comments:

--------------------------------------------------------------------------------------------------
"""

import pdb
import crypto_funcs

print('\n --- Challege 8 ---\n')

#
# The file is hex encoded.
#
# 1) Read the file directly into a list using a different technique than the in previous challenge
#    files. Interesting to look at different ways to read data from the input files.
# 
# 2) Split each string into 16 byte blocks and count the number of dupe blocks
#    for each line. Note that a new routine was put into crypto_funcs to detect duplicate blocks
#    in a byte string. See dupe_blocks in crypto_funcs.
#
# 3) Print result and see what we got.
#

max_dupes, dupes, detected_ciphertext, linenum, detected_line = 0,0,None,1,0

for ciphertext in list(open("chal8_input.txt", "r")):
    ciphertext = ciphertext.rstrip()
    #
    # Note: the number 16 literal passed into the dupe_blocks routine. To clarify what that number 
    # is, it is specific to the Challenge 8 AES-128-ECB problem. 16 is the byte length of the key
    # and is referred to in Challenge 7. So it was hard coded into this routine call as the routine
    # needs a block size.
    #
    dupes = crypto_funcs.dupe_blocks(bytearray(ciphertext, 'utf-8'),16)
    if dupes > max_dupes:
        max_dupes = dupes
        detected_ciphertext = ciphertext
        detected_line = linenum
    # 
    linenum += 1

# Not sure about a space being in front of the deteced ciphertext for some reason. Something to 
# checkout
print('Line #: ',detected_line, " - Dupes - ", max_dupes, " - Content: -",detected_ciphertext)
