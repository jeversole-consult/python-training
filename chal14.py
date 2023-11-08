"""
--------------------------------------------------------------------------------------------------
 Challenge 14 - 

 Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext.
aYou are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using 
all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
 
Notes:

This one points back to challenge 12 with a twist where there is now an unknown fixed length string in front of known 
(attacker) text followed by a string of text targeted for decryption. Building on the work of challenge 12 a modified
technique is used here to setup byte-at-a-time decryption of the target text. 

Technical:

Following the advice of the challenge "Stimulus/Response" that do we know and what is our approach. Did not find the
Stimulus/Response clue to be of much help. Here we are using a couple of known text variables to calculate the 
prefix length and the length of the target text. Armed with the length of the two known text strings we can setup
byte-at-a-time in front of the target text.

Also, there is a trick used to figure out the target text length. This trick exploits the block structure to find two
equal blocks. For the approach here this trick is required and it is one of those problems like solving two equations 
and two unknowns where you don't have enough information to figure out the variables and there of course is a trick
that you need to see. The trick here is not complicated if you understand it. If you don't see it then you will be left
scratching your head. 

"""
import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re
import time

print('\n --- Challege 14 ---\n')

# Preconditions:
# - This script assumes that ECB mode has already been detected so it does not do mode detection. ECB is assumed
#   as a precondition.

# Steps:
#
# 1) Initialize a variable with unkown random plaintext of unknown, but fixed length. This variable is used as the 
#    prefix component of the 3 part string used to decrypt the target text.
# 
# 2) Create a variable to use as the known text component to feed the oracle for results. This variable is
#    sandwiched between the prefix and the unknown text.
#
# 3) Create a variable to use as the unknown target/trailer text as the trailer for composit string to be
#    fed to the oracle.
# 
# 4) Pretend to create a random key and assign it to a variable.
#
# 4) Discover the block size from the oracle and the number of blocks
#
# 5) Use the AES ECB Oracle to encrypt a concatenated string of a random generated prefix + known plaintext + unknown 
#    plaintext with a key
# 
# 6) Run it through the ECB decrypt algorithm outlined in the challenge to isolate byte at a time
#    and discover the byte using a brute force search.
#

# Unknown test string base64 encoded. Pretend not to know it
data = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown_bytes = base64.b64decode(data.encode('latin-1'))
#
known_string = b''
#
# Pretend not to know this key
unknown_key  = b'YELLOW SUBMARINE'
rand_prefix  = b'random-prefix-random-prefix-random-prefix-random-prefix'

start_len = len(crypto_funcs.aes_ecb_oracle(rand_prefix + unknown_bytes, unknown_key))

# Step 1: find the block size
#
while True:
    #
    # When the length of the return byte string changes we can compute the block size based on the change in length of 
    # new crypto string and the original crypto string
    #
    new_len = len(crypto_funcs.aes_ecb_oracle(rand_prefix + known_string + unknown_bytes, unknown_key))
    if (new_len > start_len):
        block_size = new_len - start_len
        num_blocks = int(new_len/block_size)
        print('new_len = ', new_len)
        print('known_string len - ',len(known_string))
        print("Block size   - ", block_size)
        print("Total blocks - ", num_blocks)
        break
    else:
        known_string += b'A'

offset1_len = len(known_string)
offset1 = b'A' * offset1_len

# Step2: Split the encrypted unaltered string and the altered string into lists of blocks
# then, step through the lists and find the 1st blocks that don't match. This gives us the # of blocks in the 
# prefix.

tmp = crypto_funcs.aes_ecb_oracle(rand_prefix + unknown_bytes, unknown_key)
n = block_size
alist = [tmp[i:i+n] for i in range(0, len(tmp), n)]
tmp = crypto_funcs.aes_ecb_oracle(rand_prefix + offset1 + unknown_bytes, unknown_key)
blist = [tmp[i:i+n] for i in range(0, len(tmp), n)]

for i in range(len(alist)):
    if (alist[i] != blist[i]):
        num_prefix_blocks = i + 1
        last_prefix_block = blist[i]
        last_prefix_block_num = i
        break

print('Num prefix blocks = ', num_prefix_blocks)

# 
# At this point we know the following:
#  - block size
#  - the number of bytes needed to push the concatenated string past a block boundary
#  - the number of blocks required for the prefix.
# 
# We do not know
#  - the length of the prefix
#  - the length of the target text
# 
# To find the length of the prefix we can add byte at a time and compare the previous block to the
# new block. This time around we are looking for when the last block of the prefix goes equal with
# previous block. We keep a count of the number of bytes added to get there and now we can 
# calculate how long the prefix is. 
#
tmp = crypto_funcs.aes_ecb_oracle(rand_prefix + offset1 + unknown_bytes, unknown_key)
blist = [tmp[i:i+n] for i in range(0, len(tmp), n)]
offset2_len = 0

known_string2 = b'A'
i = 0
bflag = False

while True:
    #
    # In this loop we use another known string (known_string2)  
    #
    tmp = crypto_funcs.aes_ecb_oracle(rand_prefix + known_string + known_string2 + unknown_bytes, unknown_key)
    blist = [tmp[j:j+n] for j in range(0, len(tmp), n)]
    
    for k in range(1, (len(blist)-1)):
        if ((blist[k] == blist[k-1])) :
            bflag = True
            break

    if (bflag):
        break

    known_string2 += b'A'
    i += 1

offset2_len = len(known_string2)
offset2 = b'A' * offset2_len

# We still have a knarly boundary condition where the length of the unknown text falls within
# the last block of the prefix text. 
# We can now derive the prefix len and the target len with the info in handl

prefix_len = (num_prefix_blocks * block_size) - ((offset2_len + offset1_len) % block_size)
target_len = ((num_blocks - num_prefix_blocks) * block_size) - (offset2_len - offset1_len)
target_len = (start_len-prefix_len) - offset1_len 

prefix_block = rand_prefix + ((offset2_len - offset1_len) * b'A')
prefix_block = rand_prefix + (target_len * b'A')
attack_block = (b'A' * (((num_blocks - num_prefix_blocks)) * block_size) + (offset1_len * b'A'))
attack_len = len(attack_block)

# Now that we have a prefix on a block boundary we can byte-at-a-time decrypt the target string
# How do we do this? The trick is to look back to challenge 12 and borrow some code from there.
# 
# Declare some vars 
# prefix_block = b''
#
# Tricky sort of loop below. Note the early exit and the numbers it is based on. The approach is to start with
# with a attack text the size of the unknown text itself and back off one char at a time from that. When to stop is 
# one trick. The other trick is how to build the attack string for prefix/target architecture using ECB.

found_bytes   = b''
prefix_block_len = len(prefix_block)

for j in range((attack_len)-1, -1, -1):
    if (len(found_bytes) == (target_len)): #!!!!
        print('Done')   
        # Done
        break

    # For this problem prepend a fixed prefix block that is on a block boundary that enables us to use the
    # byte-a-atime method we used in challenge 12. We append a decreasing length known string to isolate 
    # the bytes of the unknown string.

    attack_block = (b'A' * j) 
    attack_block_len = len(attack_block)
    cipher_bytes = crypto_funcs.aes_ecb_oracle(prefix_block + attack_block + unknown_bytes, unknown_key)

    for k in range(256):
    # This is the single byte brute force search for the matching encrypted byte
        new_cipher_bytes = crypto_funcs.aes_ecb_oracle(prefix_block + attack_block + found_bytes + k.to_bytes(1,'little') + unknown_bytes, unknown_key)

        if (bytes(cipher_bytes)[:(prefix_block_len + attack_len)] == bytes(new_cipher_bytes)[:(prefix_block_len + attack_len)]):
            # We found a byte match
            found_bytes += k.to_bytes(1,'little')
            print('\n\n',found_bytes)
            time.sleep(1)
            break

print('Found bytes - ', found_bytes, '\n')
print("\nDone\n")

# End chal14