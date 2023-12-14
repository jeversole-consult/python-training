"""
--------------------------------------------------------------------------------------------------
 Crypto Funcs - Python functions specific to the Cryptopals Sets Challenge
 
 After working the first couple of challenges it seemed that recurring patterns were 
 showing up in the problem space. Fertile ground for a small set of focused routines. This file
 is a parking lot for a collection of routines used to solve recurring problems.

 -- Notes:
 This is a rough cut at building a very small function library to reuse for scripts. Some research was done
 on standards for documenting the function headers. It's better than nothing.
 --------------------------------------------------------------------------------------------------
"""
from collections import Counter
from collections import defaultdict
import secrets
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64
import json
import re

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
Load the values of the english character occurance into a list. If you use this module you get an english character
distribution loaded for you to use in pattern recognition statistics. For now it is hard coded.
"""
dist_english = list(occurance_english.values())

ecb_global_key = secrets.token_bytes(16)

def PKCS7_pad(text:bytes, blocksize:int) -> bytes:
    """
    This method takes a byte string and based on the length of the string returns a PKCS#7 compliant pad byte string to
    calling routine.
    
    Parameters
    ----------
    text : bytes
       Input byte string used to determine the length and values of the pad
    
    Returns
    ----------
    bytes: A PKCS#7 compliant byte string of length and value depending on the block boundaries of the input string
    """

    # Looked around and found the python method divmod that gets the padnum. Probably not the most efficient way to do it,
    # but gets the job done.
    padstr = b''
    q,r = divmod(len(text),blocksize)
    padnum = blocksize - r # The number of bytes to pad is the block size minus the remainder
    for i in range(0,(padnum)):
        padstr += padnum.to_bytes(1,'little')
    
    return(padstr)

# -- End PKCS7_pad --

def PKCS7_unpad(text:str) -> str:
    """
    This method takes a byte string and based on the length of the string returns a PKCS#7 compliant pad byte string to
    calling routine.
    
    Parameters
    ----------
    text : bytes
       Input byte string used to determine the length and values of the pad to strip
    
    Returns
    ----------
    bytes: A byte string that has PKCS#7 padding removed
    """

    # Note that the variable text is a byte string which means we can use the last byte of the string as a number.
    # Interesting expression below.

    return(text[:-text[-1]])
    
# -- End PKCS7_unpad --

def PKCS7_padchk(text:bytes, blocksize:int) -> bool:
    """
    This method takes a byte string expected to have valid PKCS7 padding and checks to see if it has valid
    padding.
    
    Parameters
    ----------
    text : bytes
       Input byte string expected to be PKCS7 padded
    
    blocksize : int
        
    Returns
    ----------
    bool: True - valid padding, False - exception or invalid padding

    Notes
    -----

    - It's not clear if the block size is needed in this routine, but I put it in there anyway just in case
    latter.

    - I put and exception handler in the code, but I'm still not sure that is needed. But, it is a means to
    test the use of exeption handling after reading extensively on python exception handling.

    """

    # Per the 
    # 

    try:
       expected_pad = b''
       given_pad = b''
       x = 0
       x = len(text) - (len(text) - text[-1])

       given_pad = text[-x:]
       for i in range(0,text[-1]):
           expected_pad += text[-1].to_bytes(1,'little')
       assert expected_pad == given_pad    
       print('Good Padding!')
       return(True)
    except Exception as e:
 #      print(e)
       print('Bad Padding!')   
       return(False)
    else:
        return(False)
    finally:
        pass
    
# -- End PKCS7_padchk --

def random_byte_str(size:int) -> bytes:
    """
    This method takes an integer as an input argument and returns a byte string of length of the input argument where all of 
    the bytes in the string have been independently selected at random. This is a solved problem in python with the module
    secrets.
    
    Parameters
    ----------
    size : int
       This is the length of the byte string to create and return.
    
    Returns
    ----------
    bytes: The result byte string of length size
    """
    # Use Python builtins for this

    return(secrets.token_bytes(size))

# -- End random_byte_string --

def aes_random_mode_encrypt(text:bytes) -> bytes:
    """
    This method takes a byte string and AES encrypts the string using the following rules:
    1) A random string function is used to generate the key of fixed length 16 bytes
    2) For CBC the IV is generated using a random byte string generator
    3) The mode to use between ECB or CBC is selected using a digital coin toss 
        
    Parameters
    ----------
    text : bytes
       The byte string to encrypt.
    
    Returns
    ----------
    bytes: The resulting encrypted byte string.
    """

    # As called for by Challenge 11 add random bytes to the front and back of byte string passed in using a 
    # range between 5 & 10
    tmp = random_byte_str(random.randint(5,10)) + text + random_byte_str(random.randint(5,10))

    # PKCS7 pad the byte string to be encrypted
    tmp = tmp + PKCS7_pad(tmp, 16)
    
    if (random.randint(1,2) == 1):
        key = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)
        return(cipher.encrypt(tmp))
    else:
        key = secrets.token_bytes(16)
        IV = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, IV)
        return(cipher.encrypt(tmp))

# -- End aes_random_mode_encrypt --

def aes_ecb_oracle(text:bytes, key:bytes) -> bytes:
    """
    This method takes a byte string, a key, ecb encrypts the string with the key, and returns it.
        
    Parameters
    ----------
    text : bytes
       The byte string to encrypt.
    key : bytes
       Key to use for encryption.
    
    Returns
    ----------
    bytes: The resulting encrypted byte string.
    """

    # PKCS7 pad the byte string to be encrypted
    tmp = text + PKCS7_pad(text, 16)
    
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.encrypt(tmp))
    
# -- End aes_ecb_oracle --

def aes_ecb_decrypt(text:bytes, key:bytes) -> bytes:
    """
    This method takes an ECB encrypted byte string and key then the decrypted plaintext.
        
    Parameters
    ----------
    text : bytes
       The byte string to encrypt.
    key : bytes
       Key to use for encryption.
    
    Returns
    ----------
    bytes: The resulting decrypted byte string.
    """
    
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.decrypt(text))
    
# -- End aes_ecb_decrypt --

def aes_mode_oracle(text):
    """
    This method currently takes a byte string of text and looks to see if it can detect which AES mode is being used to 
    encrypted text.

    Parameters
    ----------
    text : bytes
       Byte string of text to perform analyze   

    Returns
    ----------
    int: 0 - Not a block cipher
         1 - ECB block cipher detected
         2 - CBC block cipher detected
    """

    q,r = divmod(len(text), 16)
    if (r != 0):
        return(0)
    print("Dupes = ",dupe_blocks(text,16))
    if (dupe_blocks(text,16) >= 1):
        return(1) # more than 1 dupe block means it is likely ECB
    else:
        return(2) # else the block cipher is CBC

# -- End aes_mode_oracle --

def cbc(IV, key, text):
    """
    Split the input text into blocks of block_length and compute the Cipher Block Chain result for 
    the text and return

    Parameters
    ----------
    IV : bytes
       Initialization Vector for the algorithm
    key : bytes
       Byte string for the key
    text : bytes
       Byte string of text to perform operation   

    Returns
    ----------
    bytes: The result text from performing the cbc algorithm

    Notes:
    ----------
    This routine is currently a stub.

    """

# -- End cbc --


def dupe_blocks(text, block_length):
    """
    Split the input text into blocks of block_length and look for the number of duplicate blocks
    in the text.

    Parameters
    ----------
    text : bytes
       text data to be split into blocks and analyzed
    block_length : int
       length of the blocks to be analyzed

    Returns
    ----------
    int: The number of duplicate blocks found in the text input
    """
    #
    # To understand the statement below need to read up on python dictionaries. It basically says
    # when a new key is created in the dictionary its value will be initialized to -1 which handles
    # a certain counting problem for this challenge most eligantly.
    #
    dupe_cnt = defaultdict(lambda: -1)
    for i in range(0, len(text), block_length):
        block = bytes(text[i:i + block_length])
        dupe_cnt[block] += 1
    return sum(dupe_cnt.values())

# -- End dupe_blocks --

def hamming_dist(s1:bytes, s2:bytes, bitlen:int) -> int:
    """
    Compute and return the average Hamming distance for two byte strings

    Parameters
    ----------
    s1 : bytes
       string 1 for comparison
    s2 : bytes
       string 2 for comparison
    bl : int
       bit length to use for comparison
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

    return(bitdist/(z*bitlen))

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
    Compute and return the multi-byte XOR of a bytes string with a multiple byte key

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
    Given a plain `text` string formatted as bytes and a mulibyte encryption key `key`. The 
    function encrypts the text by performing XOR of all the bytes rotating through each byte of 
    the `key` sequentially.


    """
    bytenum=len(key)
    rotate,b,z = 0,b'',None
    
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

def parse_query_str(text: str) -> dict:
    """
    Parse query string

    Parameters
    ----------
    text : str
       Input test string to parse and return python dictionary
    
    Returns
    -------
    dictionary - the result of the parsed elements for the input string into pairs
    
    Notes:
    ------
    This accepts and input string expected to be the equivalent of http query string. The 
    example given for Challenge 13 is delimited like an http query string
    """
    
    # First split on the & to get a list of strings that can further split on "=" and build a dictionary
    
    pairs = dict(x.split("=") for x in text.split("&"))

    # I could do it in one fell swoop, but I broke out the return statement 

    return pairs
    
# -- End parse_query_str --


def profile_for(text: dict) -> str:
    """
    Build profile input string from dictionary

    Parameters
    ----------
    text : dict
       Input dict data structure and return string
    
    Returns
    -------
    A query string encoded with fixed uid and role
    
    Notes:
    ------
    This routine simply takes an "ordered" python dictionary, builds a query string, returns it. 
    
    There are some rules for the input email address itself in that it cannot have metacharacters in the email string. 
    All "&" and "=" are to be stripped from the input string if they happen to be in the input string.
    """
    qs = ''

    for key, value in text.items():

        # Strip the special chars from the value if they exist 
        re.sub(r'\&', r'', value) 
        re.sub(r'\=', r'', value) 
        qs = qs + key + '=' + value + '&'
    
    # Dump the trailing & on return

    return qs[:-1]
    
# -- End profile_for --

def c16f1_preappend(header: bytes, body: bytes, footer: bytes) -> bytes:
    """
    Parameters
    ----------
    header : bytes
       Header block to prepend
    body : bytes
       midsection of the resultant string
    footer : bytes
       
    Returns
    -------
    A string that is the result of concatenating header + body + footer
    
    Notes:
    ------
    This is a simple routine called for by the challenge 16 specification. The choice here is to accept 3 strings of 
    text and simply concatenate them with an additional requirement. The "body" string requires that special characters
    be escaped. The method used here for escaping chars like ';' and '=' is to replace them with the equivalent 
    ASCII encoding reference documented across internet sources. The substitution used here is from Windows 1252.

    Further note. The continuous process of encoding and decoding I find a tedious, but, necessary detail to which close 
    attention pays off. The basic mechanics of expanding one character to 3 characters, e.g. the symbol = becomes %3D, is 
    a play in this game.
    
    """
    
    # Escape the special characters in the body string. This is a brute force approach to get the job done.
    body_str = str(body, 'latin-1')
    body_str = re.sub(r';', r'%3B', body_str) 
    body_str = re.sub(r'=', r'%3D', body_str) 
    body = bytes(body_str, 'latin-1')

    return(header+body+footer) 

# -- End c16f1_preappend --

def aes_cbc_mode_encrypt(text:bytes, key:bytes, IV:bytes) -> bytes:
    """
    This method takes a byte string and a key an returns an AES CBC mode encrypted byte string using the following rules:
    1) This routine does not generate a random key since it takes the key as a parameter
    2) For CBC the IV is generated using a random byte string generator ???
        
    Parameters
    ----------
    text : bytes
       The byte string to encrypt.
    
    key : bytes
       The key to use for encryption.

    IV : bytes
       The initialization vector to use for CCB encryption.

    Returns
    ----------
    bytes: The resulting encrypted byte string.

    """

    cipher = AES.new(key, AES.MODE_CBC, IV)
    return(cipher.encrypt(text))

# -- End aes_cbc_mode_encrypt --

def aes_cbc_mode_decrypt(text:bytes, key:bytes, IV:bytes) -> bytes:
    """
    This method takes an encrypted byte string and a key an returns an AES CBC mode encrypted byte string using the following rules:
    1) This routine does not generate a random key since it takes the key as a parameter
    2) For CBC the IV is generated using a random byte string generator ???
        
    Parameters
    ----------
    text : bytes
       The byte string to encrypt.
    
    key : bytes
       The key to use for encryption.

    IV : bytes
       The initialization vector to use for CCB encryption.

    Returns
    ----------
    bytes: The resulting dencrypted byte string.

    """

    cipher = AES.new(key, AES.MODE_CBC, IV)
    return(cipher.decrypt(text))

# -- End aes_cbc_mode_decrypt --
