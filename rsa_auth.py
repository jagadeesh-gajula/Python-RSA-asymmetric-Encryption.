from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

''' asy_enc class provides RSA key pair generation and related functions'''

class asy_enc:
    ''' Default init function for intilzing public and private key pair'''
    def __init__(self):
        self.private_key = None
        self.public_key = None

    ''' This method will generate public and private key pair and put them into
    class attributes. this function needs to be explicity called for generating key pair'''
    def gen_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key = public_key

    '''this methods saves both  key pair into PEM files'''
    def save_keys(self,name):
        if self.private_key == None or self.public_key == None:
            print("Keys are not valid to save..")
            return
        pem = self.private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                                )

        with open(name + '_private_key.pem', 'wb') as f:
            f.write(pem)

        pem = self.public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )

        with open(name+'_public_key.pem', 'wb') as f:
            f.write(pem)

    ''' This method saves private key into a PEM file'''
    def save_private_key(self,key,name):
        if key == None:
            print("invalid key object...")
            return
        pem = key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                                )

        with open(name + '_private_key.pem', 'wb') as f:
            f.write(pem)


    ''' This method saves a public key into a file'''
    def save_public_key(self,key,name):
        if key == None:
            print("invalid key object...")
            return
        pem = key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )

        with open(name+'_public_key.pem', 'wb') as f:
            f.write(pem)

    ''' This method will load saved files into private key object'''
    def load_private_key(self,path):
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                                    key_file.read(),
                                    password=None,
                                    backend=default_backend()
                                    )
        return private_key


    ''' This method will load public key file into a public key object'''
    def load_public_key(self,path):
        with open(path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        return public_key

    ''' This method will take a public key object and encrypt a given message,
    Message should be in bytes format'''
    def encrypt(self,public_key,message):
        encrypted = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        return encrypted

    ''' This method will take a private key object and decrypts into original message 
    private key object should be from the same pair '''
    def decrypt(self,private_key,encrypted):
            original_message = private_key.decrypt(
                    encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            return original_message


'''
# implemention of above class

obj = asy_enc()
obj.gen_key_pair()
public_key = obj.load_public_key('keys_public_key.pem')
private_key = obj.load_private_key('keys_private_key.pem')

encrypted = obj.encrypt(public_key,b'hello sir')
print(encrypted)

decrypted = obj.decrypt(private_key,encrypted)
print(decrypted)
'''
