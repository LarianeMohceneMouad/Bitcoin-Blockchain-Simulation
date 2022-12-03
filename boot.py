import socket
import threading
import pickle
import time

# Creating boot socket
boot_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Set boot params
ip = '127.168.10.1'
port = 1234
# Socket binding
boot_socket.bind((ip, port))
# Set boot socket for listening
boot_socket.listen()

# Store agents
agents = []
# Store agents names
agents_names = []
# Store agents public keys
agents_public_key = []
# Store agents info
agents_info = []


def broadcast_agents_info(new_agents_info):
    """
    Broadcasts agents information that contains agent name and public key to connected agents
    :param new_agents_info:
    """
    for agent in agents:
        pickled_obj = pickle.dumps(new_agents_info)
        agent.send(pickled_obj)


def handle(agent):
    """
    Handle agent connection existence and broadcast agents objects to other agents
    :param agent:
    """
    while True:
        try:
            # Receiving object
            obj = agent.recv(100000)
            pass
            # Broadcasting object
            # broadcast(obj)
        except socket.error:
            # Removing the agent that has disconnected
            # Getting agent index
            index = agents.index(agent)
            # Removing agent name from the agents name list
            left = agents_names[index]
            agents_names.remove(left)
            # Removing agent public key from agents public keys list
            pkey_left = agents_public_key[index]
            agents_public_key.remove(pkey_left)
            # Removing agent info from agents info list
            agent_info_left = agents_info[index]
            agents_info.remove(agent_info_left)
            # Removing agent connection socket object from the sockets list
            agents.remove(agent)
            print(f'{left} left ')
            print(f"Current connected agents {agents_names}")
            # Updating other agents by sending the new agents info list
            broadcast_agents_info(agents_info)
            # Closing connection with the agent
            agent.close()
            break


def boot():
    """
    Establish agent connection and exchange information
    """
    print("server is listening...")
    # Agents number for attributing an agent name for each new agent automatically
    agent_number = 2
    while True:
        # Generating agent name from agent number
        agent_name = 'Agent-' + str(agent_number)
        # Accepting agent connection
        agent, address = boot_socket.accept()
        # Sending agent name
        agent.send(agent_name.encode("ascii"))
        # Receiving agent's public key
        p_key = agent.recv(2048)

        sock_info = agent.recv(1024).decode("ascii")
        # Adding agent to agents list
        agents.append(agent)
        # Adding agent name to agents names list
        agents_names.append(agent_name)
        # Adding agent's public key to agents public key list
        agents_public_key.append(p_key)
        print(f"Connected with {agent_name} with add {str(address)} and public key {p_key}")
        print(f"Current connected agents {agents_names}")
        # Adding agent information as a tuple (a tuple values can't be changed)
        agents_info.append((agent_name, p_key, sock_info))
        # Delaying pubic key (agents info) broadcasting (to wait for agent to complete its launch aka receive function
        # thread start)
        time.sleep(1)
        # Broadcasting agents info that contains agent name and its pubic key
        broadcast_agents_info(agents_info)
        # increment agent number to generate a new agent name from it the next time a new agent connects
        agent_number += 1

        # Launching agents handling thread
        thread = threading.Thread(target=handle, args=(agent, ))
        thread.start()


# Launching Thread
boot()
