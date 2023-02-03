"""
--------------------------------------------------------------------------------------------------_

 Challenge 4 - Find the single-character XOR'd string

 One of the 60-character strings in the file https://cryptopals.com/static/challenge-data/4.txt
 has been encrypted by single-character XOR.

 -- Notes:

 The file to analyze has been copied to the repo and named chal4_input.txt. It has 326 lines of 
 60 chars each encoded in hex. One of them has been encrypted using single byte XOR. To be clear, 
 all of the strings are encrypted, it's just that one of them is using a single byte XOR. We can 
 run our Challenge 3 code to analyze each string and see what we get.
 
 Approach 

 1) Read the file into a list of strings

 2) Setup a loop to look at each string

 3) Call the challenge 3 code against each string

 4) Examine the results

"""

from collections import Counter
import pdb
import crypto_funcs

#
# Print the challenge number
#
print('\n--- Challege 4 ---\n')

'''
And Now This
'''

hex_file = open("chal4_input.txt", "r")
data = hex_file.read()

data_list = data.split("\n")
min_fq, max_fq, fq = None, None, None

for cnt, hexline in enumerate(data_list):
    cipher_text = bytes.fromhex(hexline).decode('latin-1')
    cipher_bytes = bytes(cipher_text, 'latin-1')
    original_text, ekey, fq = crypto_funcs.sbx_decipher(cipher_bytes)

    if min_fq is None or fq < min_fq:
        min_fq = fq
        linenum = cnt
        found_text = original_text

    if max_fq is None or fq > max_fq:
        max_fq = fq

print("Line: ", str(linenum), " -> has the minimum Fitting Quotient - ", str(min_fq), "\nPlain Text = ", found_text)
print("Key = " + str(ekey))
print("\nMax fq = ", str(max_fq))


