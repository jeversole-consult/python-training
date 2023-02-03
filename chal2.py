"""
---------------------------------------------------------------------------------------------
 Challenge 2 - Fixed XOR

 Write a function that takes two equal-length buffers and produces their XOR combination.

 If your function works properly, then when you feed it the string:

 1c0111001f010100061a024b53535009181c
 ... after hex decoding, and when XOR'd against:

 686974207468652062756c6c277320657965
 ... should produce:
 
 746865206b696420646f6e277420706c6179

 See: https://cryptopals.com/sets/1/challenges/2

 -- Notes:
 
 - Below we are initializing variables with the strings provided by the challenge. How to
   effectively XOR them is an interesting problem.

---------------------------------------------------------------------------------------------
"""
print('\n --- Challege 2 ---\n')

# Hard code the input

a = '1c0111001f010100061a024b53535009181c'
b = '686974207468652062756c6c277320657965'

# Echo the variables to output 

print('a = ' + a)
print('b = ' + b + '\n')

# Remember ASCII has to be converted to binary before applying operators
# Good exercise to explore why the expression below works

cx = int(a,16) ^ int(b,16)
print('XOR = ', hex((cx)) + '\n')

