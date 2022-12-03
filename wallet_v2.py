from Crypto.PublicKey import RSA
from Crypto import Random


class Wallet:
    def __init__(self, initial_value):

        # Generating key pairs
        random_generator = Random.new().read
        rsa_key = RSA.generate(2048, random_generator)

        # Private key : Owner Private key
        self.private_key = rsa_key.exportKey()
        # Public key: Owner Public key
        self.public_key = rsa_key.publickey().exportKey()
        # Value : Wallet total value
        self.total_value = initial_value
        # Incoming outputs : list of outputs sent to this agent
        self.incoming_outputs = []

    def get_usable_private_key(self):
        return self.private_key

    def get_usable_public_key(self):
        # return self.public_key.decode("ascii")
        return self.public_key

    def get_private_key(self):
        return self.private_key.decode("ascii")

    def get_public_key(self):
        # return self.public_key.decode("ascii")
        return self.public_key.decode("ascii")

    def get_total_value(self):
        return self.total_value

    def get_incoming_outputs(self):
        return self.incoming_outputs

    def update_total_value(self, operation, amount):
        if operation == 'in':
            self.total_value += amount
        elif operation == 'out':
            self.total_value -= amount

    def update_incoming_outputs(self, output):
        self.incoming_outputs.append(output)

