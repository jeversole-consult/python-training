"""
--------------------------------------------------------------------------------------------------
 Challenge 11 - 

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts 
under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the 
plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time 
for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block 
box that might be encrypting ECB or CBC, tells you which one is happening.

Reference: https://cryptopals.com/sets/2/challenges/11

Notes:

1) This exercise requires building some support routines. First we need a key generator that returns a 16 byte key of 
randomly selected bytes. Such a routine can be developed to take in an arbitrary number for string length and return a 
random string of bytes of that size. This same key generator routine can be used to meet another requirement to generate
a string of random bytes based on the length provided to the routine.

2) An encryption routine that takes in a string and randomly chooses a mode to use and returns the encrypted string. 

3) Once an encrypted string is returned and given you don't know which mode is in use detect which mode was used.

4) There is a lot of support in Python for mathematical functions like random number generation.

5) Judgement is used as to how much to research existing solutions versus trying to do it on your own. As far as a random
byte generator that problem is solved with an import library. Generating a random number within a range is a solved problem.
How to use it in the fashion described by the problem statement requires some more thought.

6) Test cases. Getting plain text input from a file is used with this exercise. Many experiments with basic strings can be
used to test the exercise requirement, but a block of plain text was used from a basic text file with newlines as opposed to
one big string. This approach ended up causing a lot of headaches, but lead to a closer understanding of encoding and how to
deal with it.

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re

print('\n --- Challege 11 ---\n')

#
# The test file is plain text.
#
# 1) Read the file in as one big string. 
# 
# 2) Convert the string to bytes
#
# 3) Call the encrypt routine
# 
# 4) Call the detect method to determine if it is a block cipher and the mode
# 
# 5) See what we got.
#

test_file = open("chal11_input.txt", "r")
data = test_file.read()
message_bytes = bytes(data, 'utf-8')

#
# Testing - The strings below are left in the code to demonstrate that the downstream code is working. Initial findings show
# there is a dependency on the plain text used. Apparently, text from Moby Dick does not readily exhibit patterns in the 
# plain text so the test file was altered to dupe some lines. 
# 
#data = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
#data = 'YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE\nYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE'
#data = 'Aside from those more obvious considerations touching Moby Dick, which could not but occasionally awaken in any man’s soul some alarm, there was another thought, or rather vague, nameless horror concerning him, which at times by its intensity completely overpowered all the rest; and yet so mystical and well nigh ineffable'
#data = 'YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE'

message_bytes = bytes(data, 'utf-8')

# Try this run 5 times and how the random
for i in range(0,5):
    cipher_bytes = crypto_funcs.aes_random_mode_encrypt(message_bytes)
    aes_mode_detect = crypto_funcs.aes_mode_oracle(cipher_bytes)
    if (aes_mode_detect == 0):
        print('i = ', i, " - detect = ", aes_mode_detect, " Not a block cipher")
    elif (aes_mode_detect == 1):
        print('i = ', i, " ECB block cipher detected")
    else:
        print('i = ', i, " CBC block cipher detected")

