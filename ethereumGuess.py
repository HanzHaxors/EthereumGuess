from random import SystemRandom
from eth_keys import keys
from os import system as cmd
import sys, threading, win10toast

"""
LIBRARY
https://github.com/vergl4s/ethereum-mnemonic-utils/
"""
import binascii
import hashlib
import hmac
import struct

from base58 import b58encode_check
from ecdsa.curves import SECP256k1

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'
LEDGER_ETH_DERIVATION_PATH = "m/44'/60'/0'/0"


def mnemonic_to_bip39seed(mnemonic, passphrase):
    """ BIP39 seed from a mnemonic key.
        Logic adapted from https://github.com/trezor/python-mnemonic. """
    mnemonic = bytes(mnemonic, 'utf8')
    salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)


def bip39seed_to_bip32masternode(seed):
    """ BIP32 master node derivation from a bip39 seed.
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """
    k = seed
    h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code


def derive_public_key(private_key):
    """ Public key from a private key. 
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """

    Q = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator
    xstr = Q.x().to_bytes(32, byteorder='big')
    parity = Q.y() & 1
    return (2 + parity).to_bytes(1, byteorder='big') + xstr


def derive_bip32childkey(parent_key, parent_chain_code, i):
    """ Derives a child key from an existing key, i is current derivation parameter.
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """

    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & BIP32_PRIVDEV) != 0:
        key = b'\x00' + parent_key
    else:
        key = derive_public_key(parent_key)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % BIP32_CURVE.order
        if a < BIP32_CURVE.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)

    return key, chain_code


def fingerprint(public_key):
    """ BIP32 fingerprint formula, used to get b58 serialized key. """

    return hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()[:4]


def b58xprv(parent_fingerprint, private_key, chain, depth, childnr):
    """ Private key b58 serialization format. """

    raw = (
        b'\x04\x88\xad\xe4' +
        bytes(chr(depth), 'utf-8') +
        parent_fingerprint +
        childnr.to_bytes(4, byteorder='big') +
        chain +
        b'\x00' +
        private_key)

    return b58encode_check(raw)


def b58xpub(parent_fingerprint, public_key, chain, depth, childnr):
    """ Public key b58 serialization format. """

    raw = (
        b'\x04\x88\xb2\x1e' +
        bytes(chr(depth), 'utf-8') +
        parent_fingerprint +
        childnr.to_bytes(4, byteorder='big') +
        chain +
        public_key)

    return b58encode_check(raw)


def parse_derivation_path(str_derivation_path):
    """ Parses a derivation path such as "m/44'/60/0'/0" and returns 
        list of integers for each element in path. """

    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")

    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(BIP32_PRIVDEV + int(i[:-1]))
        else:
            path.append(int(i))
    return path


def mnemonic_to_private_key(mnemonic, str_derivation_path=LEDGER_ETH_DERIVATION_PATH, passphrase=""):
    """ Performs all convertions to get a private key from a mnemonic sentence, including:
    
            BIP39 mnemonic to seed
            BIP32 seed to master key
            BIP32 child derivation of a path provided
        
        Parameters:
            mnemonic -- seed wordlist, usually with 24 words, that is used for ledger wallet backup
            str_derivation_path -- string that directs BIP32 key derivation, defaults to path
                used by ledger ETH wallet 
    """

    derivation_path = parse_derivation_path(str_derivation_path)

    bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)

    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)

    private_key, chain_code = master_private_key, master_chain_code

    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)

    return private_key

######################################
## EthereumGuess
## (c) HanzHaxors 2020
######################################

# Process argv
argv = len(sys.argv) > 1
if argv:
	if sys.argv[1] == "-h" or sys.argv[1] == "-help" or sys.argv[1] == "--help":
		print(f"""
	EthereumGuess
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Usage:
	py ethereumGuess.py [-h|-help|--help|-v]


	Argument			Description
	-h or -help or --help		Shows this message
	-v				Verbose mode
	""")
		cmd("pause")
		exit()

try:
	maxt = int(input("[#] Maximum try: "))
except:
	print("[!] Please input number only!")
	exit()

# basephrase = sys.argv[-2].split() if " " in sys.argv[-2] else input("[#] Base phrase: ").split()
# expected = sys.argv[-1] if sys.argv[-1].startswith("0x") else input("[#] Expected address: ")
basephrase = input("[#] Base phrase: ").split()
expected = input("[#] Expected address: ")

private_key = None
addr = ""
found = False
rng = SystemRandom()
res = set()

for _ in range(maxt): # TODO: Threading
	nowlen = len(res)
	
	while nowlen == len(res):
		rng.shuffle(basephrase)
		res.add(' '.join(basephrase))
	
	private_key = mnemonic_to_private_key(" ".join(basephrase))

	priv_key = keys.PrivateKey(private_key)
	pub_key = priv_key.public_key
	addr = pub_key.to_checksum_address()
		
	if argv:
		if sys.argv[1] == "-v":
			print(f"[i] Trying {' '.join(basephrase)}")
			print(f"[i] Result: {addr}")
	
	print(f"[{_}] Trying...", end="\r")
	
	if addr == expected or found:
		# found added here to stop other threads
		# when one of them found the key (TODO)
		found = True
		print("\n")
		break

# Threading
# howmuch = int(input("[#] Thread number to use: "))
# threads = list()
# for i in range(howmuch):
	# t = threading.Thread(target=guess, daemon=True)
	# threads.append(t)

# for thread in threads:
	# thread.start()
	# thread.join()

if found:
	print(f"""
Key Found!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~""")
	print(f"[i] Private: {private_key.hex()}")
	print(f"[i] Address: {addr}")
	
	try:
		win10toast.ToastNotifier().show_toast(title="Key Found!",msg=f"PrivateKey: {private_key.hex()}\nAddress: {addr}", threaded=True, duration=10)
	except:
		pass
else:
	print(f"[i] Not found after trying {str(maxt)} times")
	
	try:
		win10toast.ToastNotifier().show_toast(title="Nothing Found...",msg=f"After trying {str(maxt)} times", threaded=True, duration=10)
	except:
		pass
cmd("pause")