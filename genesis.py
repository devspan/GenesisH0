import hashlib
import binascii
import struct
import array
import os
import time
import sys
import argparse
import importlib
import scrypt
import pivx_quark_hash as quark_hash
from construct import *

def main():
    options = get_args()
    algorithm = get_algorithm(options)
    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print_block_info(options, hash_merkle_root)
    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", type=int, default=int(time.time()), help="the (unix) time when the genesis block is created")
    parser.add_argument("-z", "--timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks", help="the pszTimestamp found in the coinbase of the genesis block")
    parser.add_argument("-n", "--nonce", type=int, default=0, help="the first value of the nonce that will be incremented when searching the genesis hash")
    parser.add_argument("-a", "--algorithm", default="SHA256", help="the PoW algorithm: [SHA256|scrypt|X11|X13|X15|quark]")
    parser.add_argument("-p", "--pubkey", default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f", help="the pubkey found in the output script")
    parser.add_argument("-v", "--value", type=int, default=5000000000, help="the value in coins for the output, full value (exp. in bitcoin 5000000000 - To get other coins value: Block Value * 100000000)")
    parser.add_argument("-b", "--bits", type=int, help="the target in compact representation, associated to a difficulty of 1")
    args = parser.parse_args()
    if not args.bits:
        if args.algorithm in ["scrypt", "X11", "X13", "X15"]:
            args.bits = 0x1e0ffff0
        else:
            args.bits = 0x1d00ffff
    return args

def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15", "quark"]
    if options.algorithm in supported_algorithms:
        return options.algorithm
    else:
        sys.exit("Error: Given algorithm must be one of: " + str(supported_algorithms))

def create_input_script(psz_timestamp):
    psz_prefix = ""
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'
    script_prefix = '04ffff001d0104' + psz_prefix + len(psz_timestamp).to_bytes(1, byteorder='big').hex()
    print(script_prefix + psz_timestamp.encode('utf-8').hex())
    return bytes.fromhex(script_prefix + psz_timestamp.encode('utf-8').hex())

def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey + OP_CHECKSIG)

def create_transaction(input_script, output_script, options):
    transaction = Struct(
        "version" / Bytes(4),
        "num_inputs" / Byte,
        "prev_output" / Bytes(32),
        "prev_out_idx" / Int32ul,
        "input_script_len" / Byte,
        "input_script" / Bytes(len(input_script)),
        "sequence" / Int32ul,
        "num_outputs" / Byte,
        "out_value" / Bytes(8),
        "output_script_len" / Byte,
        "output_script" / Bytes(0x43),
        "locktime" / Int32ul
    )
    tx_data = b'\x00' * (127 + len(input_script))
    tx = transaction.parse(tx_data)
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(input_script)
    tx.input_script = input_script
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', options.value)
    tx.output_script_len = 0x43
    tx.output_script = output_script
    tx.locktime = 0 
    return transaction.build(tx)

def create_block_header(hash_merkle_root, time, bits, nonce):
    block_header = Struct(
        "version" / Bytes(4),
        "hash_prev_block" / Bytes(32),
        "hash_merkle_root" / Bytes(32),
        "time" / Bytes(4),
        "bits" / Bytes(4),
        "nonce" / Bytes(4)
    )
    genesisblock = block_header.parse(b'\x00'*80)
    genesisblock.version = struct.pack('<I', 1)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)
    genesisblock.hash_merkle_root = hash_merkle_root
    genesisblock.time = struct.pack('<I', time)
    genesisblock.bits = struct.pack('<I', bits)
    genesisblock.nonce = struct.pack('<I', nonce)
    return block_header.build(genesisblock)

def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash..')
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2**(8*((bits >> 24) - 3))
    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            if algorithm in ["X11", "X13", "X15"]:
                return (header_hash, nonce)
            return (sha256_hash, nonce)
        else:
            nonce += 1
            data_block = data_block[0:len(data_block) - 4] + struct.pack('<I', nonce)

def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = b""
    if algorithm == 'scrypt':
        header_hash = scrypt.hash(data_block, data_block, 1024, 1, 1, 32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = sha256_hash
    elif algorithm == 'X11':
        try:
            xcoin_hash = importlib.import_module("xcoin_hash")
        except ImportError:
            sys.exit("Cannot run X11 algorithm: module xcoin_hash not found")
        header_hash = xcoin_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X13':
        try:
            x13_hash = importlib.import_module("x13_hash")
        except ImportError:
            sys.exit("Cannot run X13 algorithm: module x13_hash not found")
        header_hash = x13_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X15':
        try:
            x15_hash = importlib.import_module("x15_hash")
        except ImportError:
            sys.exit("Cannot run X15 algorithm: module x15_hash not found")
        header_hash = x15_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'quark':
        header_hash = quark_hash.getPoWHash(data_block)[::-1]
    return sha256_hash, header_hash

def is_genesis_hash(header_hash, target):
    return int(header_hash.hex(), 16) < target

def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write("\r{} hash/s, estimate: {} h".format(hashrate, generation_time))
        sys.stdout.flush()
        return now
    else:
        return last_updated

def print_block_info(options, hash_merkle_root):
    print("algorithm: {}".format(options.algorithm))
    print("merkle hash: {}".format(hash_merkle_root[::-1].hex()))
    print("pszTimestamp: {}".format(options.timestamp))
    print("pubkey: {}".format(options.pubkey))
    print("time: {}".format(options.time))
    print("bits: {}".format(hex(options.bits)))

def announce_found_genesis(genesis_hash, nonce):
    print("genesis hash found!")
    print("nonce: {}".format(nonce))
    print("genesis hash: {}".format(genesis_hash.hex()))

# GOGOGO!
if __name__ == "__main__":
    main()
