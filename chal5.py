"""
--------------------------------------------------------------------------------------------------
 Challenge 5 - Implement repeating-key XOR
 
 Here is the opening stanza of an important work of the English language:

 Burning 'em, if you ain't quick and nimble
 I go crazy when I hear a cymbal
 Encrypt it, under the key "ICE", using repeating-key XOR.
 
 In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext
 will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
 
 It should come out to:
 
 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
 a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

 Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your
 password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with
 this.

 -- Notes:

 To tackle this problem we need to iterate of a python byte string and keep track of where we are
 so that we can use the chars of the repeating key in order. A little tricky, but not too bad. We
 can reuse code already written to accomplish the task.
--------------------------------------------------------------------------------------------------
"""
# Import needed functions
import crypto_funcs

# Initialize strings with test data
#
# WRONG
# a = b"Burning 'em, if you ain't quick and nimble\n"
# b = b'I go crazy when I hear a cymbal'
#
# RIGHT
# a = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
#
# Note - the example shown on the website is tricky. In order to get the result shown you have to
# concatenate the two strings with a newline embedded. That newline is implicit in the example
# on the website so you have to figure this out on your own. This is shown by the string below.
#
# Something else to be aware of with a multibyte XOR across a block of text. All of the text for a
# block must be submitted to the multi_byte_xor function. The reason is that the encryption key 
# rotates across every byte in the byte string so the function only works for one string.
#

a = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
print("\nByte string input = ",a)

x = crypto_funcs.multi_byte_xor(a, b'ICE')
print('\n')
print ("Hex = ", x.hex())

# Can we go back to where we came from?
#
b = crypto_funcs.multi_byte_xor(x, b'ICE')
print('\nAnother XOR and we get back the original =>\n ', b)