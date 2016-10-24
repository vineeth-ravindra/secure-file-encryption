'''
Author 		: Vineeth Ravindra
Description : This file provides a solution to securely encrypt 
				a file that needs to sent via email. This 
				program uses and has dependency on python 
				cryptography library. 
			  The soution provided makes use of a mix of both 
			  symetric and asymetric cryptography. 
			  The Assymetric keys are used to exchange keys and
			  sign the keys. 
			  Symetric Crypto us used encrypt the payload 
Usage 		:
			python fcrypt.py -[e/d] dest_key
			sender_key input_plaintext_file ciphertext_file

'''
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
'''
	asymmetric : Type -> class
	purpose : Export interface to cryptography library to 
				perform RSA (Assymetric encryptio)
	Features : Provides interface for
				a) RSA Encryption
				b) RSA Decryption
				c) Generate digital signatures
				d) Verify digital Signatures
	Notes	:  When file run with -e mode
			  	self.publicKey : Public key of destination
			  	self.privateKey: Private Key of Sender
			   When file run with -d mode
			    self.publicKey : public key of sender
			    self.privateKey: private key of destination

'''
class asymmetric:
	def __init__(self):
		self.privateKey = None
		self.publicKey = None

	def loadKey(self,file,type):
		if type == "private":
			with open(file, "rb") as key_file:
				try:
					self.privateKey = serialization.load_pem_private_key(
						key_file.read(),
						password=None,
						backend=default_backend())
				except:
					print "Error while Loading key "+file
					sys.exit(0)
		elif type == "public" :
			with open(file, "rb") as key_file:
				try:
					self.publicKey = serialization.load_pem_public_key(
						key_file.read(),
						backend=default_backend())
				except:
					print "Error while loading key "+file
					sys.exit(0)

	def signMessage(self,message):
		signer = self.privateKey.signer(
			padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())
		try:
			signer.update(message)
			signature = signer.finalize()
		except:
			print "Unable to sign file"
			sys.exit(0)
		return signature

	def verifySignature(self,message,signature):
		verifier = self.publicKey.verifier(
			signature,
			padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
			),hashes.SHA256())
		verifier.update(message)
		try:
			verifier.verify()
		except:
			return False
		return True

	def encryptMessage(self,message):
		try:
			cipherText = self.publicKey.encrypt(
							message,
							padding.OAEP(
							mgf=padding.MGF1(algorithm=hashes.SHA1()),
							algorithm=hashes.SHA1(),
							label=None))
		except:
			print "Unable to perform asymetric encryption"
			sys.exit(0)
		return cipherText

	def decryptMessage(self,message):
		try:
			plainText = self.privateKey.decrypt(
				message,
				padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA1()),
				algorithm=hashes.SHA1(),
				label=None))
		except:
			print "Unable to perform symetric decryption"
			sys.exit(0)
		return plainText


'''
	symetric : Type -> class
	purpose : Export interface to cryptography library to 
				perform AES (Symetric encryptio)
	Features : Provides interface for
				a) AES Encryption
				b) AES Decryption
				c) encryptor crypto object
				d) decryptor crypto object
'''
class symetric:
	def __init__(self):
		self.key = None

	def loadKey(self,key):
		self.key = key

	def getKey(self):
		return self.key

	def getEncryptor(self,iv):
		return Cipher(
		    algorithms.AES(self.key),
		    modes.CFB(iv),
		    backend=default_backend()
		).encryptor()
		return 
	
	def getDecryptor(self,iv):
		return Cipher(
				algorithms.AES(self.key),
				modes.CFB(iv),
				backend=default_backend()
			).decryptor()

	def encryptMessage(self,message,encryptor):
		try:
			return encryptor.update(message)+encryptor.finalize()
		except:
			print "Error while symetric encryption"
			sys.exit(0)
		

	def decrypt(self,cipherText,decryptor):
		try:
			return decryptor.update(cipherText) +decryptor.finalize()
		except:
			print "Error While symetric decryption"
			sys.exit(0)
		
'''
	controll : Type -> class
	purpose : Encrypt or decrypt given file 
	
'''		

class controll:
	def __init__(self):
		self.args = sys.argv
		if len(self.args) != 6:
			print "Inproper usage\nPlease use correct format\n"
			print "python fcrypt.py -[e/d] destination_[public/private]_key_filename\n \
			sender_[public/private]_key_filename input_plaintext_file ciphertext_file"
			sys.exit(0)
		if self.args[1] == '-d' or self.args[1] == '-e':
			self.mode = True if self.args[1] == '-e' else False
			self.destKey = self.args[2]
			self.senderKey = self.args[3]
			self.inFile = self.args[4]
			self.outFile = self.args[5]
		else:
			print "Inproper usage\nPlease use correct format\n"
			print "python fcrypt.py -[e/d] destination_[public/private]_key_filename\n \
			sender_[public/private]_key_filename input_plaintext_file ciphertext_file"
			sys.exit(0)
		
	'''
		_encryptFile : Input -> empty
					Output -> Cipher text file. The cipher text file has infomation
						in following format
						<iv,{key}dest_public,{key}sender_private,message>
	'''
	

	def _encryptFile(self):
		iv = os.urandom(16)
		symKey = os.urandom(16)
		a = asymmetric()
		
		a.loadKey(self.destKey,"public")
		a.loadKey(self.senderKey,"private")
		symKeyEncrypted = a.encryptMessage(symKey)
		
		s = symetric()
		s.loadKey(symKey)
		encryptor = s.getEncryptor(iv)
		with open(self.inFile,'rb') as inFile:
			plainText = inFile.read()
			cipherText = s.encryptMessage(plainText,encryptor)
			signatureSymKey = a.signMessage(cipherText)
		return "++xoxo++".join([iv,symKeyEncrypted,signatureSymKey,cipherText])

	'''
		_decryptFile : Input -> empty
					Output -> Plaintext text file. 
	'''
	def _decryptFile(self):
		a = asymmetric()
		s = symetric()
		a.loadKey(self.senderKey,"public")
		a.loadKey(self.destKey,"private")		
		with open(self.inFile, 'rb') as in_file:
			msg = in_file.read()
			msg = msg.split("++xoxo++")
			iv = msg[0]
			symKey = a.decryptMessage(msg[1])
			if not a.verifySignature(msg[3],msg[2]) :
				print "Invalid Message signatures\nSomething fishy might have happened"
				sys.exit(0)
			
			s.loadKey(symKey)
			decryptor = s.getDecryptor(iv)
			return s.decrypt(msg[3],decryptor)


	def main(self):
		if self.mode:
			msg = self._encryptFile()
			with open(self.outFile,'wb') as out_file:
				out_file.write(msg)
		else:
			msg = self._decryptFile()
			with open(self.outFile,'wb') as out_file:
				out_file.write(msg)

if __name__ == "__main__":
    controll().main()
