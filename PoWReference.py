#coding=utf-8

import binascii, functools, hashlib

try:
    hashlib.sha3_256
except AttributeError:
    import sha3

try:
    hashlib.blake2b
except AttributeError:
    from pyblake2 import blake2b
    hashlib.blake2b = blake2b

from hashlib import sha256, sha3_256, blake2b

def from_hex(x):
    return binascii.unhexlify(x)

def to_hex(x):
    return binascii.hexlify(x).decode()

def sha3(x):
    return sha3_256(x).digest()

def blake32(x):
    return blake2b(x, digest_size=32).digest()

def blake64(x):
    return blake2b(x, digest_size=64).digest()

null = None
false = False
true = True

# Stratum object from network traffic

# Case 1
stratum_subscribe = {"id":"2","result":[[["mining.notify","0000dc72"],["mining.set_difficulty","0000dc72"]],"0000dc72",24],"error":null}
stratum_notify = {"id":null,"method":"mining.notify","params":["14b1382355c0b673","00000000000004ad18a5e8e90dfdaa283bea53fda6b0a802ec11d9586f0c67cd","a9f9832d20c9ff19f0d1105f43b66843b44721d1bb01db40931ad698930a6e9f","23683415b03c2a23120a805676198bb61b3a1e8e8defb4f5c56d0c6e682cfad1","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","00000000","1a083449","5e4264a2"]}
stratum_submit = {"params":["donate.001","14b1382355c0b673","c92400d6","5e4264a2","d4c9ec4f","0000000000000000000000000000000000000000000000000000000000000000"],"id":"3","jsonrpc":"2.0","method":"mining.submit"}

# Case 2
stratum_subscribe = {"id":"2","result":[[["mining.set_difficulty","02c04c54"],["mining.notify","02c04c54"]],"02c04c54",24],"error":null}
stratum_notify = {"params":["gTvTEeyryQ","00000000000002727e0912b2ce13c28cc347e23370c87498cdf207f187ff0f55","c438bed3d40fc67a05a4a877c4e3bc6f3cda9b9f71587b38a2abdfc78188771e","9ccd9f939dd1cf967af9fb9e7d8c8d178f13873db3f1e72dadc4bcc6a5ea2c79","1e2b44242c8ee57154496f66e9941d20aca69a3a239cb55a622f9b5d162a53ff","0000000000000000000000000000000000000000000000000000000000000000","00000000","1a06d8bf","5e49aca4"],"id":null,"method":"mining.notify"}
stratum_submit = {"params":["hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l.001","gTvTEeyryQ","a24b95bd","5e49aca4","2fbb6bc9","0000000000000000000000000000000000000000000000000000000000000000"],"id":"3","jsonrpc":"2.0","method":"mining.submit"}

# Case 3
stratum_subscribe = {"id":"2","result":[[["mining.set_difficulty","02c05bfd"],["mining.notify","02c05bfd"]],"02c05bfd",24],"error":null}
stratum_notify = {"id":null,"params":["gTvmBBIuLW","00000000000005a6d2c1716b4ce0077d06cf6d6337ac2392f9e75821183fdea8","791dcae1813b2cd031208efad11c8dbc735195869e126cccd9eda08674eb0b0f","2716257b59d2ec7784efa547dc9cf035b489b9349477918303952458e7bd9714","1e2b44242c8ee57154496f66e9941d20aca69a3a239cb55a622f9b5d162a53ff","0000000000000000000000000000000000000000000000000000000000000000","00000000","1a06e782","5e49aa25"],"method":"mining.notify"}
stratum_submit = {"params":["hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l.001","gTvmBBIuLW","aa923a8b","5e49aa25","73a37ddb","0000000000000000000000000000000000000000000000000000000000000000"],"id":"3","jsonrpc":"2.0","method":"mining.submit"}

# Check if both jobids match

notify_jobid = stratum_notify['params'][0]
submit_jobid = stratum_submit['params'][1]
assert notify_jobid == submit_jobid, 'jobid mismatch'

# Parse stratum object

nonce1 = from_hex(stratum_subscribe['result'][-2])
extranonce_length = stratum_subscribe['result'][-1]

previousblockhash = from_hex(stratum_notify['params'][1])
merkleroot = from_hex(stratum_notify['params'][2])
witnessroot = from_hex(stratum_notify['params'][3])
treeroot = from_hex(stratum_notify['params'][4])
reservedroot = from_hex(stratum_notify['params'][5])
version = from_hex(stratum_notify['params'][6])[::-1]
bits = from_hex(stratum_notify['params'][7])[::-1]
ntime = from_hex(stratum_notify['params'][8])[::-1]
assert len(stratum_notify['params']) == 9

nonce2 = from_hex(stratum_submit['params'][2])
ntime = from_hex(stratum_submit['params'][3])[::-1]
nonce = from_hex(stratum_submit['params'][4])[::-1]
mask = from_hex(stratum_submit['params'][5])
assert len(stratum_submit['params']) == 6

# Compute the PoWHash

extranonce = (nonce1 + nonce2 + b'\x00' * extranonce_length)[:extranonce_length]

padding = bytes(previousblockhash[i] ^ treeroot[i] for i in range(32))
subhash = blake32(extranonce + reservedroot + witnessroot + merkleroot + version + bits)
maskhash = blake32(previousblockhash + mask)
commithash = blake32(subhash + maskhash)
prehead = nonce + ntime + b'\x00' * 4 + padding[:20] + previousblockhash + treeroot + commithash
sharehash = blake32(blake64(prehead) + padding[:32] + sha3(prehead + padding[:8]))
powhash = bytes(sharehash[i] ^ mask[i] for i in range(32))
print(to_hex(powhash))

