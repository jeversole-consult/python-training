"""
--------------------------------------------------------------------------------------------------
 Challenge 13 - ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, 
whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, 
make a role=admin profile.

Reference: https://cryptopals.com/sets/2/challenges/13

Notes:

This one required some more thought to figure exactly what the use case is. Also, the encoding between the display format
and the actual input and output format. The work flow interpreted here is as follows:

1) We have an encrypted structured cookie that we discover is encoded using ECB and hence we can decode it. We can
also discover the key.

2) After we decode it we see a standard query string structure with key/value pairs. We can take apart those KV pairs 
and examine what's in there. In this case we see a "role" variable. Might it be possible to construct a new token we could pass 
that would let us achieve admin privilege?

3) If the target is dumb enough, the answer is yes. The next step is to understand how we can exploit the ECB block cypher 
to forge a new token to escalte privilege. 

4) How to pull this off appears to have shaped the name "Cut and Paste" in the challenge. If I build an input string knowing
the block boundaries ahead of time, combined with my knowledge of the structure of the content, I can design an exploit. 

5) The exploit looks at the decrypted contents, finds the "role" variable, uses an oracle with some logic to build 
an extra block that lines up on a specific boundary where the value of the role variable is at the beginning of the block.
Once we get encrypted blocks back we can swap them out and escalate role/privilege for uid 10 and from there... 

--------------------------------------------------------------------------------------------------
"""

import pdb
import base64
import crypto_funcs
from Crypto.Cipher import AES
import re

print('\n --- Challege 13 ---\n')

qstr = 'foo=bar&baz=qux&zap=zazzle'
kv = crypto_funcs.parse_query_str(qstr)

# Print out the dictionary structure and note that it is ordered as of v3.7 python
print('Using a python dictionary structure for a standard key/value pair construct:\n')
print('Structure for ', qstr, " is:\n", kv, '\n')

# Now set kv to the test data specified 
kv = {'email':'foo@bar.com',
      'uid': '10',
      'role': 'user'}

#
profile = crypto_funcs.profile_for(kv)
print('Test profile string: ', profile)

# Pretend not to know this key, i.e. it is randomly generated, but for testing we can use a fixed value. Can sub in a routine
# to generate a random key after tackling the core problem.

unknown_key  = b'YELLOW SUBMARINE'

# Build the attack profile string as specified by the challenge and then encrypt it 
kv = {'email':'foooo@bar.admin\v\v\v\v\v\v\v\v\v\v\vcom',
      'uid': '10',
      'role': 'user'}

profile = crypto_funcs.profile_for(kv)
print('Test target profile string: ', repr(profile))

ciphertxt = crypto_funcs.aes_ecb_oracle(bytes(profile,'latin-1'), unknown_key)
print('Test target cipher string:  ', ciphertxt)

tmp = ciphertxt.decode('latin-1')
# Split the string into 16 byte blocks
n = 16
blist = [tmp[i:i+n] for i in range(0, len(tmp), n)]
print('\nEncrypted block list = ', blist, '\n')

# Overwrite the last block with the 2nd block and delete the second block

blist[3] = blist[1] # overwrite the end block

blist.pop(1) # delete the block in the middle used to get an admin role
print('Altered block list = ', blist, '\n')

# Reassemble the blocks
ciphertxt = ''.join(blist)

plaintxt = crypto_funcs.aes_ecb_decrypt(bytes(ciphertxt,'latin-1'), unknown_key)
plaintxt = crypto_funcs.PKCS7_unpad(plaintxt)
print('New plaintxt = ', repr(plaintxt.decode('latin-1')))

# Convert to key value pairs

kv = crypto_funcs.parse_query_str(plaintxt.decode('latin-1'))

# Print out the dictionary structure and note that it is ordered
print('Dictionary form:\n', kv)


# End chal13
