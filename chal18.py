"""
--------------------------------------------------------------------------------------------------
 Challenge 17 - The CBC padding oracle

 This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.

Cryptography Services | NCC Group

Notes:

This is another one of those where getting detail around the use case helps me in understanding the attack. I'm one of those
that works back from the real world case to the abstract math. In this use case we have some preconditions going on.

Preconditions:
- An understanding of the term "Padding Oracle" is assumed.
- The oracle is of course simulated to understand the challenge.  

After researching padding oracles I'm looking at them as servers you can feed input and they will return output. For this
exercise we will assume that the oracle accepts unlimited inputs to illustrate the vulnerability. We can construct and send
as many messages as we want to the oracle and use a binary response like pass/fail to adjust input and decrypt the plaintext
without a key. Rather interesting if I must say so myself.

Out of the abstract and into a real world example. Let's say I am able to talk to a webserver API that uses JWTs. The HTTP
protocol provides the capability to send blocks of information in the header of a message or on a query string and it is 
these blocks of data that we are interested in when looking to find things like secrets. When I look at the data provided 
by this challenge I notice that it is base64 encoded, but I'm not sure if that matters. They are just random strings, 
and we will find out soon enough if decoding is assumed.

Back to the vulnerability. First, unlimited calls to the oracle is a start. That means the oracle is not smart enough to 
detect that bad guys are messing with it. Let's say we're talking to an API server that uses an encrypted string 
a.k.a. token we can see. This token could come in various forms, and the trick is we can see it, we can mess with it, 
and resend it in an API call. The return code from the API is informative if it is a padding oracle. It's gonna tell us 
if we have good or bad padding.

Regarding programming and debugging. This exercise is tricky and the question arises as to how to iron out bugs during
initial development. The description outlines a black box where the Key and the IV are selected at random each run of the
code. I decided to fix those values in initial development so when I make mistakes is is much easier to run down the mistake.
Once I figure out the logic I can always swap back the random generation and compare that to a benchmark.

I didn't really get the solution here until I painfully traced out exactly where the specific values to XOR are located 
and the equation used to exploit the vulnerability. 
--------------------------------------------------------------------------------------------------
"""
import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re
import time
import secrets

print('\n --- Challege 17 ---\n')

# Initialize some variables
blk_len = 16
#
# I leave these key and IV constants in place for future debugging
# key = b'YELLOW SUBMARINE'
# IV  = b'0000000000000000'
key = secrets.token_bytes(blk_len)
IV  = secrets.token_bytes(blk_len)
attack_blk = bytearray(secrets.token_bytes(blk_len))

# Call function 1. Note in this case we are creating the key and IV outside of the function and passing it in.
# We could use some oops techniques to create an object to be reused, but maybe that will come in an upgrade

cipher_txt_bytes = crypto_funcs.c17_func1(key, IV, blk_len)
print("\nCipher text - ", cipher_txt_bytes)

# Split the cipher text into blocks and then decrypt block at a time.
blist = [cipher_txt_bytes[i:i+blk_len] for i in range(0, len(cipher_txt_bytes), blk_len)]

ptext_blk = bytearray([0x00]*blk_len)
prev_cipher_blk = b''
cur_cipher_blk_num = len(blist) - 1
ptext_list = []
ptext = b''

for target in blist[::-1]:
    #
    # For this exercise we are assuming that the IV is known. That is what we need to decrypt the first block of
    # the cipher text. Note that we are decrypting the blocks last to first.
    if (cur_cipher_blk_num >0):
        # Set the previous block from blist
        prev_cipher_blk = blist[cur_cipher_blk_num-1]
    else:
        # Use the IV as the previous block to get the first block
        prev_cipher_blk = IV
    # 
    # A few things going on here. First the exploit is possible due to some really interesting binary arithmetic that allows
    # the hacker to break up some cipher text into CBC blocks and traverse these blocks one at a time. You need two blocks 
    # to pull this off. Prepend a hack block to a block of cipher text and give it to the oracle. The oracle is a bit
    # dumb so it sends back error messages interpreted as bad padding so a byte at a time brute force attack is used to
    # find a value that delivers good padding. The padding error is used to find a corresponding intermediate byte that is
    # then used to XOR with the previous block cipher text to find the byte of plain text. No key necessary because of how
    # the equations work. Using the decrypted plaintext we move onto the intermediate value of the next byte and step
    # backwards through the bytes. Once one block is finished we move onto the next block.
    # 
    for j in range(blk_len-1,-1,-1):
        for k in range(256):
            attack_blk[j] = k
            if (crypto_funcs.c17_func2(attack_blk+target, key, IV, blk_len)):
                ptext_blk[j] = (k ^ (blk_len - j)) ^ prev_cipher_blk[j]
                break 

        # Move on to the next byte. To do that we use the previous byte we just discovered to derive a new value for the
        # attack block that works with the next padding level, e.g. when we move from \x01 to \x02\x02 we need to first
        # update the last byte of the attack block to \x02 XOR last byte of prev_cipher_blk ^ discovered plaintext byte.
        # Then we brute force the next byte looking for valid padding. Note, this needs to be done in a loop to gen new
        # values from each found byte based on the padding we're looking for.

        if (j>0):
            for i in range(blk_len-j):
              attack_blk[blk_len-i-1] = (blk_len-j+1) ^ prev_cipher_blk[blk_len-i-1] ^ ptext_blk[blk_len-i-1]
              # print("attack_blk = ", attack_blk)
        else:
            # We're done with this block. Decrement our counter and move on to the next block
            cur_cipher_blk_num -= 1 
            ptext_list.append(ptext_blk.copy())
#
# Print the plaintext base64 encoded and decoded strings. Note that the text was decrypted in reverse order so we have to
# keep that in mind when building the plaintext string from the plaintext block list.

for blk in ptext_list[::-1]:
    ptext += blk

print("\nDescrypted text - ", ptext)
print("\nBase 64 decoded - ", base64.b64decode(ptext))

print('\n --- End Challege 17 ---\n')