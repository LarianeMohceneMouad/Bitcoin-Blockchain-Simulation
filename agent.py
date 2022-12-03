import pickle
import random
import socket
import threading
import time
from tkinter import *
from cffi.backend_ctypes import xrange, long

from block import *
from transaction import *
from wallet import Wallet

'''
Added : Peer to peer
Important note: when using the transaction's id that is a the send public key you have to encode it first 
Next feature to add : the block is supposed to be received with empty previous hash block : Done
Next : compare transactions when receiving a block : Done 
NEXT FEATURE :  Add nonce and target feature

last thing added : full transactions check (whether block exists or not) and proof of work working
'''

# Setting up binding params
ip = '127.168.10.1'
port = 1234

# list used for blocks and transactions storage
blockchain = []
transactions = []

# to store the updated miners list everytime
miners_list = None
directly_connected_agents = []
incoming_miners_sockets = []
incoming_miners_names = []
outgoing_miners_names = []
outgoing_miners_sockets = []
outgoing_miners_pkeys = []
# Declaring block and transaction variables to be accessed as global variables later (needed for gui access)
block = Block(None, None)
local_block_copy = Block(None, None)
transaction = Transaction(None, None, None)
rcv_transaction = Transaction(None, None, None)

# Setting up socket
conn_agent = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connecting
conn_agent.connect((ip, port))

# For now the initial wallet value will be random------- FOR NOW

# Creating wallet
agent_wallet = Wallet(random.randint(0, 1000))

# Receiving agent name automatically
agent_name = conn_agent.recv(1024).decode("ascii")

# Sending public key
conn_agent.send(agent_wallet.get_usable_public_key())

# Creating listening socket ----------------------------------------------------------------------------------------
rcv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = f'127.168.10.{agent_name[agent_name.find("-") + 1:]}'
port = int(f'123{agent_name[agent_name.find("-") + 1:]}')
rcv_socket.bind((ip, port))
rcv_socket.listen()
print(f'listener socket created with ip {ip} and {port}')


# Done -------------------------------------------------------------------------------------------------------------
# Creating listener handler ----------------------------------------------------------------------------------------


def miners_listener():
    print("Waiting for potential miners...")
    global incoming_miners_names
    global incoming_miners_sockets
    while True:
        miner_sock, address = rcv_socket.accept()
        miner_name = miner_sock.recv(1024).decode("ascii")
        print('connection established > Miner name ', miner_name, ' with socket  ', miner_sock, 'via address ', address)
        incoming_miners_sockets.append(miner_sock)
        incoming_miners_names.append(miner_name)


def server_listener(server):
    global miners_list
    global incoming_miners_names
    while True:
        try:
            # Receiving pickled object
            r_obj = server.recv(100000)
            # Unpickling object
            r_obj = pickle.loads(r_obj)
            # If it's and information update (other agents joined)
            if type(r_obj) == list:
                new_miners_list = r_obj
                # update_logs(f"miners list update: {new_miners_list}")
                for miner in new_miners_list:
                    miner_name = miner[0]
                    miner_pkey = miner[1]
                    miner_ip, miner_port = sock_info_unpacker(miner[-1])
                    if miner_name != agent_name and miner_name not in outgoing_miners_names:
                        # Setting up socket
                        miner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        # Connecting
                        miner_sock.connect((miner_ip, int(miner_port)))
                        miner_sock.send(agent_name.encode("ascii"))
                        outgoing_miners_sockets.append(miner_sock)
                        outgoing_miners_names.append(miner_name)
                        outgoing_miners_pkeys.append(miner_pkey)
                        update_logs(f"new connection node {miner_name} | public key {miner_pkey}")
                        update_logs(f"miners list {outgoing_miners_names}")
                        update_logs(f"public keys {outgoing_miners_pkeys}")
                        miner_recv_thread = threading.Thread(target=receive_object, args=(miner_sock,))
                        miner_recv_thread.start()

        except socket.error:
            print("Server disconnected")
            server.close()
            break


handle_miner_thread = threading.Thread(target=server_listener, args=(conn_agent,))
handle_miner_thread.start()

boot_thread = threading.Thread(target=miners_listener)
boot_thread.start()

# Done ----------------------------------------------------------------------------------------------------------------
conn_agent.send((ip + '-' + str(port)).encode("ascii"))


def sock_info_unpacker(sock_info_obj):
    sock_ip, sock_port = sock_info_obj.split('-')
    return sock_ip, sock_port


def broadcast(obj):
    """
    Broadcasting requested object to all other connected agents
    :param obj:
    """
    for miner in incoming_miners_sockets:
        miner.send(obj)


def content(obj):
    """
    Display object content, even complex object contents such as Block, as a dictionary of values
    """
    import json

    j_trans = json.dumps(obj, indent=4, default=lambda o: o.__dict__)
    return str(json.loads(j_trans))


def get_merkle_root(trans):
    import hashlib

    def trans_hash(t):
        return hashlib.sha256(hashlib.sha256(content(t.get_header()).encode('ascii')).hexdigest().encode('ascii')).hexdigest()

    def hash_branch(a, b):
        return hashlib.sha256(hashlib.sha256((a + b).encode('ascii')).hexdigest().encode('ascii')).hexdigest()

    if bool(trans):
        branches = [trans_hash(t) for t in trans]
        while len(branches) > 1:
            if (len(branches) % 2) == 1:
                # branches.append(hash_branch(branches[-1], branches[-1]))
                branches.append(branches[-1])
            update_logs(branches)
            branches = [hash_branch(a, b) for (a, b) in zip(branches[0::2], branches[1::2])]
        update_logs(branches[0])
        return branches[0]


def proof_of_work(header, target_value):
    import hashlib
    for nonce_value in xrange(2 ** 32):
        header.set_target(target_value)
        header.set_nonce(nonce_value)
        print('testing with nonce ', nonce_value)
        hash_result_value = hashlib.sha256(
            (hashlib.sha256((content(header) + str(nonce_value)).encode('ascii')).hexdigest()).encode('ascii')).hexdigest()
        print('result ', hash_result_value)

        # check if this is a valid result, below the target
        if long(hash_result_value, 16) < target_value:
            print(f"Success with nonce {nonce_value} Hash is {hash_result_value}")
            return nonce_value


def target_calculator(diff_bits):
    return 2 ** (256 - diff_bits)


def check_nonce(header, nonce_value, target_value):
    import hashlib
    print('checking nonce result ')
    hash_result_value = hashlib.sha256(
        (hashlib.sha256((content(header) + str(nonce_value)).encode('ascii')).hexdigest()).encode('ascii')).hexdigest()
    print(long(hash_result_value, 16) < target_value)
    return long(hash_result_value, 16) < target_value


def create_transaction():
    """
    This function creates a transaction object
    :return: None (Uses global variable)
    """
    global transaction
    # Create transaction header
    header = TransactionHeader('protocol version', agent_wallet.get_public_key(), 'sender hash', str(dt.datetime.now()),
                               'signature')
    # Create transaction inputs
    input1 = Input('previous tx 1', 'index 1', 'script_sig 1')
    input2 = Input('previous tx 2', 'index 2', 'script_sig 2')
    inputs = TransactionInputs([input1, input2])
    # Create transaction outputs
    output1 = Output('5000 USD', 'script_pub_key 1')
    output2 = Output('10000 USD', 'script_pub_key 2')
    outputs = TransactionOutputs([output1, output2])
    # Create transaction
    transaction = Transaction(header, inputs, outputs)
    # adding transaction to transactions list
    transactions.append(transaction)
    # Displaying operation on the GUI
    update_logs(f'Transaction created  | time stamp : {transaction.get_header().get_timestamp()}')
    if bool(block.exist()):
        block.update_transactions(transaction)
        clear_trans_log()
        display_trans()


def create_block():
    """
    This function creates a block
    :return:
    """
    global block
    # Just supposing that there are three used protocol version (v1, v2, v3), each block use one of them.
    block_version = random.choice(['v1', 'v2', 'v3'])
    # Just supposing that there are different targets ('Easy', 'Medium', 'Hard'), each block use one of them.
    # block_target = None
    # Random block id from 0-10 just how it's in the 'support'
    block_id = random.randint(0, 10)
    # Creating block header
    block_header = BlockHeader(block_id, block_version, None, None)
    # Getting the current transactions list
    block_transactions = transactions.copy()
    # Creating the block
    block = Block(block_header, block_transactions)
    # Displaying operation on the GUI
    update_logs(f"block created | Block index: {block.get_block_header().get_index()}")


def send_obj(snd_obj):
    # Sys library is used to get block object size
    import sys

    global local_block_copy
    global blockchain
    global transaction
    global block
    global transactions
    local_block_chain = blockchain.copy()
    if bool(snd_obj.exist()):
        # If the object is a block, we calculate and complete the block header before sending it
        if type(snd_obj) == Block:
            # If the block is not empty
            if bool(snd_obj.get_transactions()):
                # Getting block size and and setting up the block size value in the b block header
                snd_obj.get_block_header().set_block_size(sys.getsizeof(snd_obj))
                # Calculate the merkle root value and set its value in the current block header
                snd_obj.get_block_header().set_merkle_root(get_merkle_root(snd_obj.get_transactions()))
                # target = target_calculator(random.randint(16, 24))
                target = target_calculator(16)
                update_logs('mining block...')
                start_time = time.time()
                nonce = proof_of_work(snd_obj.get_block_header(), target)
                snd_obj.get_block_header().set_target(target)

                end_time = time.time()
                elapsed_time = int(end_time - start_time)
                update_logs(f"Nonce found {nonce} for target {target}")
                update_logs(f"Elapsed Time: {elapsed_time} seconds ")

                snd_obj.get_block_header().set_nonce(nonce)

                update_proof_of_work_info(nonce, elapsed_time)
                # Pickling block (serialisation encoding)
                pickled_obj = pickle.dumps(snd_obj)
                # Sending block
                # conn_agent.send(pickled_obj)
                broadcast(pickled_obj)
                update_logs(f"Object : {type(snd_obj)} sent")

                if bool(blockchain):
                    # If the current block is not the first bloc, then we set the prev hash bock of its header
                    # by hashing the previous block
                    last_block = local_block_chain.pop()
                    last_block_header = last_block.get_hash_header_block()
                    snd_obj.get_block_header().set_hash_prev_block(last_block_header)
                else:
                    # If this current block is the first block (genesis block) that the prev hash block value is '0000'
                    snd_obj.get_block_header().set_hash_prev_block('0000')
                update_logs(f"block validated")
                # adding to local blockchain after validating the block
                update_logs(f"Adding local block to blockchain")
                # Adding block to blockchain
                blockchain.append(block)
                update_logs(f"Block chain")
                update_logs(blockchain)
                if bool(blockchain) or bool(block.exist()):
                    update_blockchain_info(block)
                # Clearing object value after sending it, to keep track of the existence of the object and avoid sending empty
                # objects to other agents
                local_block_copy = block
                block = Block(None, None)
                # All current transactions are sent within this block, therefore the transactions list must be cleared
                transactions.clear()
                update_block_info(block)
                # clear_proof_of_work_info()
            else:
                update_logs("ERROR :  Can not send block")
                update_logs("INFO :  Block transactions is empty")
        elif type(snd_obj) == Transaction:
            # Pickling block (serialisation encoding)
            pickled_obj = pickle.dumps(snd_obj)
            # Sending block
            # conn_agent.send(pickled_obj)
            broadcast(pickled_obj)
            update_logs(f"Object : {type(snd_obj)} sent")
            # Clearing object value after sending it, to keep track of the existence of the object and avoid sending empty
            # objects to other agents
            transaction = Transaction(None, None, None)

    else:
        # If we attempt to send an empty object (for debugging purposes)
        update_logs(f"Error : Failed to send requested object, {type(snd_obj)} Object not found" + "\n")
        update_logs(f"Solution :  Create object {type(snd_obj)} before attending to send it " + "\n")


def receive_object(sock):
    global blockchain
    global transactions
    global miners_list
    global incoming_miners_names
    global block
    global rcv_transaction
    global miners_list
    local_block_chain = blockchain.copy()
    new_transactions = []
    while True:
        try:
            # Receiving pickled object
            r_obj = sock.recv(100000)
            # Unpickling object
            r_obj = pickle.loads(r_obj)
            # If it's a block
            if type(r_obj) == Block:
                clear_proof_of_work_info()
                update_logs(f"Received block {r_obj} with id {r_obj.get_block_header().get_index()}")
                update_logs(f"Block info")
                update_logs(content(r_obj))
                # Checking if local block
                if local_block_copy.get_hash_header_block() != r_obj.get_hash_header_block():
                    print(content(r_obj.get_block_header()))
                    rcv_nonce = r_obj.get_block_header().get_nonce()
                    rcv_target = r_obj.get_block_header().get_target()
                    rcv_header = r_obj.get_block_header()
                    update_logs(f'checking nonce {rcv_nonce} for target {rcv_target}')
                    if check_nonce(rcv_header, rcv_nonce, rcv_target):
                        update_logs('nonce and target checked')
                        # Check received block merkle root
                        update_logs('checking merkle root')
                        if r_obj.get_block_header().get_merkle_root() == get_merkle_root(r_obj.get_transactions()):
                            update_logs(f"Merkle root checked")
                            # Adding block to blockchain
                            blockchain.append(r_obj)
                            update_logs(f"Adding received block to blockchain")
                            if bool(local_block_chain):
                                # If the current block is not the first bloc, then we set the prev hash bock of its header
                                # by hashing the previous block
                                last_block = local_block_chain.pop()
                                last_block_header = last_block.get_hash_header_block()
                                r_obj.get_block_header().set_hash_prev_block(last_block_header)
                            else:
                                # If this current block is the first block (genesis block) that the prev hash block value is '0000'
                                r_obj.get_block_header().set_hash_prev_block('0000')
                            if bool(blockchain) or bool(block.exist()):
                                update_blockchain_info(r_obj)
                            update_logs(f"Block chain")
                            update_logs(blockchain)
                            if bool(block.exist()):
                                update_logs(f"Comparing current block transactions with received block transactions")
                                received_transactions_content = [content(t) for t in r_obj.get_transactions()]
                                local_transactions_content = [content(t) for t in block.get_transactions()]
                                for ltc in local_transactions_content:
                                    if ltc not in received_transactions_content:
                                        new_transactions.append(ltc)
                                        update_logs(new_transactions)
                                update_logs("Updating current block transactions")
                                update_logs("New transactions")
                                update_logs(new_transactions)
                                block.set_transactions(new_transactions)
                                clear_trans_log()
                                display_trans()
                            else:
                                update_logs(f"Comparing current local transactions with received block transactions")
                                received_transactions_content = [content(t) for t in r_obj.get_transactions()]
                                local_transactions_content = [content(t) for t in transactions]
                                for ltc in local_transactions_content:
                                    if ltc not in received_transactions_content:
                                        new_transactions.append(ltc)
                                        update_logs(new_transactions)
                                update_logs("Updating current local transactions")
                                update_logs("New transactions")
                                update_logs(new_transactions)
                                transactions = new_transactions
                        else:
                            update_logs("Invalid merkle root ")
                            update_logs("Discarding received block")
                    else:
                        update_logs('Invalid nonce for target')
                        update_logs("Discarding received block")
            # If it's a transaction
            elif type(r_obj) == Transaction:
                rcv_transaction = r_obj
                # Transaction
                update_logs(f"Received transaction {r_obj}")
                # Transaction Info
                update_logs(f"Transaction info")
                update_logs(content(r_obj))
                # Adding transaction to transactions list
                transactions.append(r_obj)
                # Adding transaction to the current block (if there's one)
                if bool(block.exist()):
                    block.update_transactions(r_obj)
                    clear_trans_log()
                    display_trans()
        except socket.error as e:
            # Handling receiving object error
            update_logs("ERROR : receive failure ")
            update_logs(f"ERROR INFO : {e}")
            miner_index = outgoing_miners_sockets.index(sock)
            miner_name = outgoing_miners_names[miner_index]
            outgoing_miners_names.remove(miner_name)
            incoming_miners_names.remove(miner_name)
            incoming_sock = incoming_miners_sockets[miner_index]
            incoming_miners_sockets.remove(incoming_sock)
            outgoing_miners_sockets.remove(sock)
            update_logs(f'Miner : {miner_name} disconnected')
            update_logs(f"Current connected agents {incoming_miners_names}")
            sock.close()
            break


# GUI------------------------------------------------------------------------------------------------------------------

# Window


root = Tk()
root.title('Blockchain')
root.geometry('800x800')
root.iconbitmap("logo.ico")

# Buttons
b1 = Button(root, text='create Transaction', command=lambda: [create_transaction()])
b1.place(x='10', y='10', height=50, width=110)
b2 = Button(root, text='send Transaction', command=lambda: [send_obj(transaction)])
b2.place(x='10', y='70', height=50, width=110)
b3 = Button(root, text='create block', command=lambda: [create_block(), update_block_info(block), clear_trans_log(),
                                                        display_trans()])
b3.place(x='10', y='130', height=50, width=110)
b4 = Button(root, text='send block', command=lambda: [send_obj(block), send_op_log(block), clear_trans_log()])
b4.place(x='10', y='190', height=50, width=110)
b5 = Button(root, text='hash block')
b5.place(x='10', y='250', height=50, width=110)
b5 = Button(root, text='mine block')
b5.place(x='10', y='310', height=50, width=110)
b5 = Button(root, text='check Transaction')
b5.place(x='10', y='370', height=50, width=110)

# BlockchainInformation
block_header_information_labelframe = LabelFrame(root, text="Blockchain information", font=('Arial', 15), bg="gray79")
block_header_information_labelframe.place(x='130', y='0', height=240, width=220)
block_info_frame = Frame(block_header_information_labelframe, bg="gray79")
block_info_frame.pack(fill=BOTH)
block_labelframe_length = Label(block_info_frame, text="Blockchain length")
block_labelframe_length.pack(fill=X)
prev_block_info_frame = Frame(block_info_frame, bg="gray79")
prev_block_info_frame.pack(fill=BOTH)
block_header_information_labelframe = LabelFrame(prev_block_info_frame, text="Previous Block header",
                                                 font=('Arial', 13), bg="gray79")
block_header_information_labelframe.pack(fill=BOTH)
block_info_frame = Frame(block_header_information_labelframe, bg="gray79")
block_info_frame.pack(fill=BOTH)
prev_block_labelframe_index = Label(block_info_frame, text="index")
prev_block_labelframe_index.pack(fill=X)
prev_block_labelframe_block_size = Label(block_info_frame, text="block_size")
prev_block_labelframe_block_size.pack(fill=X)
prev_block_labelframe_version = Label(block_info_frame, text="version")
prev_block_labelframe_version.pack(fill=X)
prev_block_labelframe_timestamp = Label(block_info_frame, text="timestamp")
prev_block_labelframe_timestamp.pack(fill=X)
prev_block_labelframe_hash_prev_block = Label(block_info_frame, text="hash_prev_block")
prev_block_labelframe_hash_prev_block.pack(fill=X)
prev_block_labelframe_nonce = Label(block_info_frame, text="nonce")
prev_block_labelframe_nonce.pack(fill=X)
prev_block_labelframe_target = Label(block_info_frame, text="target")
prev_block_labelframe_target.pack(fill=X)
prev_block_labelframe_merkle_root = Label(block_info_frame, text="merkle_root")
prev_block_labelframe_merkle_root.pack(fill=X)

# Block header Information
block_header_information_labelframe = LabelFrame(root, text="Current Block header", font=('Arial', 15), bg="gray79")
block_header_information_labelframe.place(x='130', y='250', height=210, width=220)
block_info_frame = Frame(block_header_information_labelframe, bg="gray79")
block_info_frame.pack(fill=BOTH)
block_labelframe_index = Label(block_info_frame, text="index")
block_labelframe_index.pack(fill=X)
block_labelframe_block_size = Label(block_info_frame, text="block_size")
block_labelframe_block_size.pack(fill=X)
block_labelframe_version = Label(block_info_frame, text="version")
block_labelframe_version.pack(fill=X)
block_labelframe_timestamp = Label(block_info_frame, text="timestamp")
block_labelframe_timestamp.pack(fill=X)
block_labelframe_hash_prev_block = Label(block_info_frame, text="hash_prev_block")
block_labelframe_hash_prev_block.pack(fill=X)
block_labelframe_nonce = Label(block_info_frame, text="nonce")
block_labelframe_nonce.pack(fill=X)
block_labelframe_target = Label(block_info_frame, text="target")
block_labelframe_target.pack(fill=X)
block_labelframe_merkle_root = Label(block_info_frame, text="merkle_root")
block_labelframe_merkle_root.pack(fill=X)

# Current block Transactions
current_block_labelframe = LabelFrame(root, text="Current Block Transactions", font=('Arial', 15), bg="gray79")
current_block_frame = Frame(current_block_labelframe, bg="gray79")
current_block_labelframe.place(x='370', y='0', height=300, width=430)
# Creating transaction Scrollable bar
h = Scrollbar(current_block_labelframe, orient='horizontal')
h.pack(side=BOTTOM, fill=X)
v = Scrollbar(current_block_labelframe)
v.pack(side=RIGHT, fill=Y)
trans_log = Text(current_block_labelframe, width=15, height=15, wrap=NONE, xscrollcommand=h.set, yscrollcommand=v.set)
trans_log.pack(side=TOP, fill=X)
h.config(command=trans_log.xview)
v.config(command=trans_log.yview)

# Proof of work
proof_of_work_labelframe = LabelFrame(root, text="Proof of Work", font=('Arial', 15), bg="gray79")
proof_of_work_labelframe.place(x='130', y='480', height=100, width=200)
pow_nonce = Label(proof_of_work_labelframe, text="Nonce found : None")
pow_nonce.pack(fill=BOTH)
pow_et = Label(proof_of_work_labelframe, text="Time elapsed : - ")
pow_et.pack(fill=BOTH)

# Logs
logs_labelframe = LabelFrame(root, text="Logs", font=('Arial', 15), bg="gray79")
logs_frame = Frame(logs_labelframe, bg="gray79")
logs_frame.pack()
logs_labelframe.place(x='370', y='360', height=300, width=430)
# Creating logs Scrollable bar
h = Scrollbar(logs_labelframe, orient='horizontal')
h.pack(side=BOTTOM, fill=X)
v = Scrollbar(logs_labelframe)
v.pack(side=RIGHT, fill=Y)
log = Text(logs_labelframe, width=15, height=15, wrap=NONE, xscrollcommand=h.set, yscrollcommand=v.set)
log.pack(side=TOP, fill=X)
h.config(command=log.xview)
v.config(command=log.yview)


def update_trans_log(trans):
    # Converting the object to a json dict inorder to print the object's values
    j_trans = json.dumps(trans, indent=4, default=lambda o: o.__dict__)
    txt = str(json.loads(j_trans))
    # Displaying the transaction content
    trans_log.insert(END, txt + "\n")


def clear_trans_log():
    """
    This function clears the current block transactions list
    """
    global trans_log
    global current_block_labelframe
    global current_block_frame
    global h
    global v
    current_block_labelframe = LabelFrame(root, text="Current Block Transactions", font=('Arial', 15), bg="gray79")
    current_block_frame = Frame(current_block_labelframe, bg="gray79")
    current_block_labelframe.place(x='370', y='0', height=300, width=430)
    h = Scrollbar(current_block_labelframe, orient='horizontal')
    h.pack(side=BOTTOM, fill=X)
    v = Scrollbar(current_block_labelframe)
    v.pack(side=RIGHT, fill=Y)
    trans_log = Text(current_block_labelframe, width=15, height=15, wrap=NONE, xscrollcommand=h.set,
                     yscrollcommand=v.set)
    trans_log.pack(side=TOP, fill=X)
    h.config(command=trans_log.xview)
    v.config(command=trans_log.yview)


def update_logs(log_txt):
    """
    This function add texts as logs in the logs area of the GUI
    """
    log_txt = str(log_txt)
    log.insert(END, log_txt + "\n")


def send_op_log(obj):
    """
    This function deals with GUI messages when sending and receiving objects
    """
    global trans_log
    if type(obj) == Transaction:
        if bool(block.exist()):
            display_trans()


def display_trans():
    """
    This function displays the list of transactions of the current new created block
    """
    # Delaying function 0.5 sec to make sure all agents received the transaction
    for trans in block.get_transactions():
        # Converting the object to a json dict inorder to print the object's values
        j_trans = json.dumps(trans, indent=4, default=lambda o: o.__dict__)
        txt = str(json.loads(j_trans))
        # Displaying the transaction content
        trans_log.insert(END, txt + "\n")


def update_block_info(new_block):
    """
    This function updates the Blockchain information frame content, by displaying the header information of the
    new created block
    :param new_block:
    """
    if bool(new_block.exist()):
        # Getting block header
        header = new_block.get_block_header()
        # Updating block header components frames text
        block_labelframe_index.config(text="Id : " + str(header.get_index()))
        block_labelframe_block_size.config(text="Size : " + str(header.get_block_size()))
        block_labelframe_version.config(text="Protocol version : " + str(header.get_version()))
        block_labelframe_timestamp.config(text="Timestamp : " + str(header.get_timestamp()))
        block_labelframe_hash_prev_block.config(text="Previous block hash : " + str(header.get_hash_prev_block()))
        block_labelframe_nonce.config(text="Nonce : " + str(header.get_nonce()))
        block_labelframe_target.config(text="Target : " + str(header.get_target()))
        block_labelframe_merkle_root.config(text="Merkle root : " + str(header.get_merkle_root()))
    else:
        block_labelframe_index.config(text="Id : None")
        block_labelframe_block_size.config(text="Size : None")
        block_labelframe_version.config(text="Protocol version : None")
        block_labelframe_timestamp.config(text="Timestamp : None")
        block_labelframe_hash_prev_block.config(text="Previous block hash : None")
        block_labelframe_nonce.config(text="Nonce : None")
        block_labelframe_target.config(text="Target : None")
        block_labelframe_merkle_root.config(text="Merkle root : None")


def update_proof_of_work_info(nonce, elapsed_time):
    pow_nonce.config(text="Nonce found : " + str(nonce))
    pow_et.config(text="Elapsed time : " + str(elapsed_time) + " sec")


def clear_proof_of_work_info():
    pow_nonce.config(text="Nonce found : None")
    pow_et.config(text="Time elapsed : - ")


def update_blockchain_info(prev_block):
    global blockchain
    """
    This function updates the Blockchain information frame content, by displaying the header information of the
    new created block
    :param prev_block:
    """
    # Getting block header
    header = prev_block.get_block_header()
    # Updating block header components frames text
    block_labelframe_length.config(text="Blockchain length : " + str(len(blockchain)))
    prev_block_labelframe_index.config(text="Id : " + str(header.get_index()))
    prev_block_labelframe_block_size.config(text="Size : " + str(header.get_block_size()))
    prev_block_labelframe_version.config(text="Protocol version : " + str(header.get_version()))
    prev_block_labelframe_timestamp.config(text="Timestamp : " + str(header.get_timestamp()))
    prev_block_labelframe_hash_prev_block.config(text="Previous block hash : " + str(header.get_hash_prev_block()))
    prev_block_labelframe_nonce.config(text="Nonce : " + str(header.get_nonce()))
    prev_block_labelframe_target.config(text="Target : " + str(header.get_target()))
    prev_block_labelframe_merkle_root.config(text="Merkle root : " + str(header.get_merkle_root()))


def logs_init():
    """
    This function initialize displays agent name and wallet information as logs on agent launch
    """
    # Displaying agent name
    update_logs(agent_name)
    # Displaying wallet information
    update_logs("wallet created...")
    update_logs("Private key ")
    update_logs(agent_wallet.private_key)
    update_logs("Public key ")
    update_logs(agent_wallet.public_key)
    update_logs("Total value ")
    update_logs(agent_wallet.total_value)
    update_logs("Incoming outputs ")
    update_logs(agent_wallet.incoming_outputs)


logs_init()

root.mainloop()
