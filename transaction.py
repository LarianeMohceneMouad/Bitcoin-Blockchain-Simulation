import json
import hashlib


def content(obj):
    """
    Display object content, even complex object contents such as Block, as a dictionary of values
    """
    j_trans = json.dumps(obj, indent=4, default=lambda o: o.__dict__).encode()
    return j_trans


class TransactionHeader:
    def __init__(self, version, transaction_id, sender_hash, timestamp, signature):
        # Version : related to the used protocol (32bit)
        self.version = version
        # Transaction Id : Transaction identifier (32bit)
        self.transaction_id = transaction_id
        # SenderHash : Hashed sender public key (256bit)
        self.sender_hash = sender_hash
        # Timestamp : Timestamp of the transaction creation
        self.timestamp = timestamp
        # Signature : (SenderHash, Timestamp) signed by the sender private key
        self.signature = signature

    def get_version(self):
        return self.version

    def get_transaction_id(self):
        return self.transaction_id

    def get_sender_hash(self):
        return self.sender_hash

    def get_timestamp(self):
        return self.timestamp

    def get_signature(self):
        return self.signature


class Input:
    def __init__(self, previous_tx, index, script_sig):
        # Previous tx : Id of the transaction tx that contains this operation (transaction)
        self.previous_tx = previous_tx
        # Index : Index in previous tx outputs list
        self.index = index
        # ScriptSig : Owner public key
        self.script_sig = script_sig

    def get_previous_tx(self):
        return self.previous_tx

    def get_index(self):
        return self.index

    def get_script_sig(self):
        return self.script_sig


class Output:
    def __init__(self, value, script_pub_key):
        # Value : Transported value
        self.value = value
        # ScriptPubKey : Public key of the receiver
        self.script_pub_key = script_pub_key

    def get_value(self):
        return self.value

    def get_script_pub_key(self):
        return self.script_pub_key


class TransactionInputs:
    def __init__(self, inputs_list):
        # Inputs list : List of inputs (sent by one or multiple receivers)
        self.inputs_list = inputs_list
        # Input counter : Number of inputs
        self.in_counter = len(inputs_list)

    def get_in_counter(self):
        return self.in_counter

    def get_inputs_list(self):
        return self.inputs_list


class TransactionOutputs:
    def __init__(self, outputs_list):
        # Outputs list : List of outputs (sent to one or multiple receivers)
        self.outputs_list = outputs_list
        # Output counter : Number of outputs
        self.out_counter = len(outputs_list)

    def get_out_counter(self):
        return self.out_counter

    def get_outputs_list(self):
        return self.outputs_list


class Transaction:
    def __init__(self, header, inputs, outputs):
        self.header = header
        self.inputs = inputs
        self.outputs = outputs

    def get_header(self):
        return self.header

    def get_inputs(self):
        return self.inputs

    def get_outputs(self):
        return self.outputs

    def exist(self):
        return self.header

    def get_hash(self):
        d_hash = hashlib.sha1()
        d_hash.update(content(self.header))
        print(d_hash.hexdigest())
        return str(d_hash.hexdigest())


