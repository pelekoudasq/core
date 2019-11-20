from abc import ABCMeta, abstractmethod


class KeyManager(object, metaclass=ABCMeta):
    """
    Key-management interface
    """

    @abstractmethod
    def get_cryptosys(self):
        """
        """

    def keygen(self, private_key=None, with_proof=True):
        """
        Generates and returns a keypair

        If no private key is provided, then it will be randomly generated. If
        `with_proof` is left to its default value `True`, the public part
        will include ZK proof-of-knowledge of the private counterpart.
        """
        cryptosys = self.get_cryptosys()

        private_key, public_key = cryptosys.generate_keypair(private_key)
        proof = None
        if with_proof:
            key_proof = cryptosys._schnorr_proof(private_key, public_key)
        public_key = self.set_public_key(public_key, key_proof)
        keypair = self.set_keypair(private_key, public_key)

        return keypair


    def validate_public_key(self, public_key):
        """
        Verifies that the proof attached in the provided public key
        proves knowledge of its private counterpart.
        """
        cryptosys = self.get_cryptosys()

        key_proof = self.get_key_proof(public_key)
        if key_proof is None:
            return False

        public_key = self.get_key_value(public_key)
        if not cryptosys.validate_element(public_key):
            return False

        return cryptosys._schnorr_verify(key_proof, public_key)


    # Keypair management

    ######################################################################
    #                                                                    #
    #    By keypair is meant a dictionary of the form                    #
    #                                                                    #
    #    {                                                               #
    #        'private': exponent,                                        #
    #        'public': {                                                 #
    #            'value': GroupElement,                                  #
    #            'proof': ...                                            #
    #        }                                                           #
    #    }                                                               #
    #                                                                    #
    #   where the value of `proof` is a Schnorr-proof (or None)          #
    #                                                                    #
    ######################################################################


    def set_keypair(self, private_key, public_key):
        """
        """
        keypair = {}
        keypair['private'] = private_key
        keypair['public'] = public_key

        return keypair


    def extract_keypair(self, keypair):
        """
        """
        private_key = keypair['private']
        public_key = keypair['public']

        return private_key, public_key


    def get_private(self, keypair):
        """
        """
        private_key = keypair['private']
        return private_key


    def get_public(self, keypair):
        """
        """
        public_key = keypair['public']
        return public_key


    def get_public_value(self, keypair):
        """
        """
        value = keypair['public']['value']
        return value


    def get_public_proof(self, keypair):
        """
        """
        proof = keypair['public']['proof']
        return proof


    # Public key management

    #####################################################################
    #                                                                   #
    #    By public-key is meant a dictionary of the form                #
    #                                                                   #
    #    {                                                              #
    #        'value': GroupElement,                                     #
    #        'proof': ...                                               #
    #    }                                                              #
    #                                                                   #
    #    where the value of 'proof' is a Schnorr-proof (or None)        #
    #                                                                   #
    #####################################################################


    def set_public_key(self, element, proof=None):
        """
        """
        public_key = {}
        public_key['value'] = element
        public_key['proof'] = proof

        return public_key


    def extract_public_key(self, public_key):
        """
        """
        value = public_key['value']
        proof = public_key['proof']

        return value, proof


    def serialize_public_key(self, public_key):
        """
        """
        cryptosys = self.get_cryptosys()

        serialized = {}
        value, proof = self.extract_public_key(public_key)
        serialized['value'] = value.to_int()
        serialized['proof'] = cryptosys.serialize_scnorr_proof(proof)

        return serialized


    def deserialize_public_key(self, public_key):
        """
        """
        cryptosys = self.get_cryptosys()

        deserialized = {}
        value, proof = self.extract_public_key(public_key)
        deserialized['value'] = cryptosys.int_to_element(value)
        deserialized['proof'] = cryptosys.deserialize_schnorr_proof(proof)

        return deserialized


    def get_key_value(self, public_key):
        """
        """
        if isinstance(public_key, dict):
            return public_key['value']
        return public_key


    def get_hex_value(self, public_key):
        """
        """
        value = self.get_key_value(public_key)
        return value.to_hex()


    def get_int_value(self, public_key):
        """
        """
        value = self.get_key_value(public_key)
        return value.to_int()


    def get_key_proof(self, public_key):
        """
        """
        proof = public_key.get('proof')
        return proof


    def combine_public_keys(self, initial, public_keys):
        """
        """
        combined = initial
        for public_key in public_keys:
            combined = combined * public_key
        return combined
