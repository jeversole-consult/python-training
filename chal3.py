"""
--------------------------------------------------------------------------------------------------_

 Challenge 3 - Single byte XOR cipher

 The hex encoded string:
 
 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 ... has been XOR'd against a single character. Find the key, decrypt the message.
 
 You can do this by hand. But don't: write code to do it for you.
 
 How? Devise some method for "scoring" a piece of English plaintext. 
 Character frequency is a good metric. Evaluate each output and choose the one with the best score.

 See: https://cryptopals.com/sets/1/challenges/3

 -- Notes:

 In a single byte XOR we have plain text that we encrypt on a byte boundary using a 
 single byte (8 bit) key. We XOR each plain text byte with the same byte to get an encrypted
 byte. The key to this exercise is that you have prior knowledge of the cipher being used.
 With that knowledge you can use statistical analysis to find key.
 
 In the code below we are using an import file crypto_funcs. This file serves to illustrate 
 a simple way to capture python methods in a file to reuse. These routines were written on-the-fly
 as pieces of the same puzzle were needed to solve problems. In this case Challenges 1, 2 & 3 have 
 recurring encoding and decoding needs, not to mention decyption needs. We are using  
 crypto_funcs.py for help on that front.

--------------------------------------------------------------------------------------------------_
"""
import crypto_funcs
from collections import Counter


print('\n --- Challege 3 ---\n')

# Hard code the input
cipher_text_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

cipher_text = bytes.fromhex(cipher_text_hex).decode('utf-8')

print('\nPrint out the cipher text and the byte encoding\n')
print('Cipher = ', cipher_text)
cipher_bytes = bytes(cipher_text, 'utf-8')
print('Bytes cipher = ', cipher_bytes, '\n')

'''
And Now This
'''

# Call sbx_decipher to get the work done

original_text, ekey, fq = crypto_funcs.sbx_decipher(cipher_bytes)

print ("Oringinal text = " + str(original_text) + '\n')
print ("Key = " + str(ekey))

