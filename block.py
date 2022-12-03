import datetime as dt


class BlockHeader:
    def __init__(self, index, version, nonce, target):
        # Index : Block identifier (32bits)
        self.index = index
        # Blocksize : (32bits)
        self.block_size = None
        # Version : version of the used protocol (32bits)
        self.version = version
        # Timestamp : Timestamp of block creation
        self.timestamp = str(dt.datetime.now())
        # Previous block hash : previous block hash for integrity (256bits)
        self.hash_prev_block = None
        # Nonce : proof of work value (32bits)
        self.nonce = nonce
        # Target :  proof of work difficulty (256bits)
        self.target = target
        # Merkle root : signature for transactions integrity
        self.merkle_root = None

    def get_index(self):
        return self.index

    def get_block_size(self):
        return self.block_size

    def get_version(self):
        return self.version

    def get_timestamp(self):
        return self.timestamp

    def get_hash_prev_block(self):
        return self.hash_prev_block

    def get_nonce(self):
        return self.nonce

    def get_target(self):
        return self.target

    def get_merkle_root(self):
        return self.merkle_root

    def set_block_size(self, s):
        self.block_size = s

    def set_merkle_root(self, trans_hash):
        self.merkle_root = trans_hash

    def set_hash_prev_block(self, block_hash):
        self.hash_prev_block = block_hash

    def set_nonce(self, nonce):
        self.nonce = nonce

    def set_target(self, target):
        self.target = target


class Block:
    def __init__(self, block_header, transactions):
        self.block_header = block_header
        self.transactions = transactions
        self.hash_header_block = hash(block_header)

    def get_block_header(self):
        return self.block_header

    def get_transactions(self):
        return self.transactions

    def get_hash_header_block(self):
        return self.hash_header_block

    def set_transactions(self, trans):
        self.transactions = trans

    def exist(self):
        return self.block_header

    def update_transactions(self, transaction):
        self.transactions.append(transaction)

    def get_last_transactions(self):
        trans = self.transactions.copy()
        return trans.pop()
