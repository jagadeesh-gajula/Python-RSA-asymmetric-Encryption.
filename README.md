# Python-RSA-asymmetric-Encryption.
Python - RSA asymmetric Encryption. 

This python code enables you:
	create public and private key pair
	Save them in pair
	load key objects
	encryption and decryption


## Usage:
	
	obj = asy_enc()

	obj.gen_key_pair()

	obj.save_keys('name')

	public_key = obj.load_public_key('keys_public_key.pem')
	private_key = obj.load_private_key('keys_private_key.pem')

	encrypted = obj.encrypt(public_key,b'hello sir')
	print(encrypted)

	decrypted = obj.decrypt(private_key,encrypted)
	print(decrypted)
