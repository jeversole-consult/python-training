"""
--------------------------------------------------------------------------------------------------
 Crypto Funcs - Python functions specific to the Cryptopals Set 1 Challenge
 
 After working the first couple of challenges it seemed that recurring patterns were 
 showing up in the problem space. Fertile ground for a small set of focused routines. This file
 is a parking lot for a collection of routines used to solve recurring problems.

 -- Notes:
 This is a rough cut at building a very small function library to reuse by scripts. There is a 
 bit of an attempt to use a standard for documenting the functions. It's better than nothing.
 --------------------------------------------------------------------------------------------------
"""
from collections import Counter

"""
English lowercase frequency table
"""
occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}

"""
Load the values of the english character occurance into a list
"""
dist_english = list(occurance_english.values())

def hamming_dist(s1:bytes, s2:bytes) -> int:
    """
    Compute and return the average Hamming distance for two byte strings

    Parameters
    ----------
    s1 : bytes
       string 1 for comparison
    s2 : bytes
       string 2 for comparison
    """
    #
    # Note: This routine expects both input byte strings to be equal in length, hence,
    # the check for matching length of the two input byte strings returning an error if
    # if they are not equal
    #
    if (len(s1) != len(s2)):
        return(0)

    dist = 0
    #
    # Sequentially XOR each byte pair of the two strings to count the number of true bits left 
    # from the XOR. This gets the Hamming distance between 2 byte strings/arrays. Iterate through 
    # the byte strings/arrays that are equivalent in length and compute the difference for each byte
    # in the array. Sum the total number of individual difference bits and divide that by the total
    # bits to take the average (normalize). Return the average.
    #
    bitdist = 0
    z = 0

    for n in s1:
        # This sums all the bits that are '1s' after the XOR
        # We need to watch out for the last bytestring which can be any length
        #
        bitdist += bin(s1[z] ^ s2[z]).count('1')
        z += 1 

    return(bitdist/(z*8))

# -- End hamming_dist --

def single_byte_xor(text: bytes, key: int) -> bytes:
    """
    Compute and return the single byte XOR of a bytes string with single byte key

    Parameters
    ----------
    text : bytes
       input byte string to XOR
    key : int
       single byte integer 

    Returns
    -------
    byte string result of XOR   
    
    Notes:
    ------
    Given a plain text `text` as bytes and an encryption key `key` as a byte integer
    in range [0, 256) the function encrypts the text by performing XOR of all the bytes 
    and the `key`. 
    """
    return bytes([b ^ key for b in text])

# -- End single_byte_xor --

def multi_byte_xor(text: bytes, key: bytes) -> bytes:
    """
    Compute and return the single byte XOR of a bytes string with single byte key

    Parameters
    ----------
    text : bytes
       input byte string to XOR
    key : int
       single byte integer 

    Returns
    -------
    byte string result of XOR   
    
    Notes:
    ------
    Given a plain text `text` as bytes and an encryption key `key` as a byte integer
    Given a plain text `text` as bytes and a mulibyte encryption key `key`. The function 
    encrypts the text by performing XOR of all the bytes rotating the byte `key` sequentially 
    depending on the length of the key.
    """
    bytenum=len(key)
    rotate=0
    b=b''
    z=None

    for a in text:
        z = a ^ key[rotate]
        b = b + z.to_bytes(1,'little')
        rotate += 1
        if (rotate == bytenum):
           rotate = 0
   
    return b

# -- End multi_byte_xor --

def compute_fitting_quotient(text: bytes) -> float:
    """
    Compute the fitting quotient

    https://www.codementor.io/@arpitbhayani/deciphering-single-byte-xor-ciphertext-17mtwlzh30

    Parameters
    ----------
    text : bytes
       input byte string to compare against the lowercase English dictionary of letters
    
    Returns
    -------
    float - the computed fitting quotient is a floating point number
    
    Notes:
    ------
    
    Given the stream of bytes `text` the function computes the fitting
    quotient of the letter frequency distribution for `text` with the
    letter frequency distribution of the English language.

    The function returns the average of the absolute difference between the
    frequencies (in percentage) of letters in `text` and the corresponding
    letter in the English Language.

    This routine enables the comparison of the distribution of an encrypted string of text 
    with the known distribution of English. While not exact it proves to be most useful in 
    finding patterns in weak encryption algorithms. 
    """
    counter = Counter(text)
    dist_text = [
        (counter.get(ord(ch), 0) * 100) / len(text)
        for ch in occurance_english
    ]
    
    # Another "one-liner" below to spend some quality time on
    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

# -- End compute_fitting_quotient --

def sbx_decipher(text: bytes) :
    """
    Single byte XOR decipher

    Parameters
    ----------
    text : bytes
       input byte string to compare against the lowercase English dictionary of letters
    
    Returns
    -------
    float - the computed fitting quotient is a floating point number
    
    Notes:
    ------
    This function deciphers an encrypted text using Single Byte XOR and returns
    the original plain text message and the encryption key.
    """
    original_text, encryption_key, min_fq = None, None, None
    
    for k in range(256):
        # we generate the plain text using encryption key `k`
        plain_text = single_byte_xor(text, k) 
        
        # we compute the fitting quotient for this decrypted plain text
        fq = compute_fitting_quotient(plain_text)
        
        # if the fitting quotient of this generated plain text is lesser
        # than the minimum seen till now `min_fq` we update.
        if min_fq is None or fq < min_fq:
            encryption_key, original_text, min_fq = k, plain_text, fq

    # return the decrypted text, key and min fq for the string with the minimum fitting quotient
    return original_text, encryption_key, min_fq

# -- End sbx_decipher --
