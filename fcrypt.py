from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os
import sys



def usage():    # function to define the synatx
    print "Please follow the following syntax:"
    print "To encrypt:\npython fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
    print "To decrypt:\npython fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file"


################################################################################################################################################
#function to serialize private key

def private_key(key_file):
    try:
           private_key_serial = serialization.load_pem_private_key(key_file.read(),password=None, backend=default_backend())


    except:
                   print "Key format not supported,(My developer is lazy)"
                   print "Supported key format: PEM"
                   sys.exit(1)

    return private_key_serial

##################################################################################################################################################
#function to serialize public key


def public_key(key_file):

     try:
         public_key_serial = serialization.load_pem_public_key(key_file.read(), backend=default_backend())


     except:
         try:
         print "Key format not supported, (My developer is lazy)"
         print "Supported key formats: PEM"
         sys.exit(1)

     return public_key_serial







#beginning of encryption module

def encrypt_sign(): # Contains the complete encryption and Signing process
    backend=default_backend()

    key=os.urandom(32) #generating Random key and IV for symmetric encryption
    iv=os.urandom(32)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend) #specifying AES algorithm using GCM mode of operation
    encryptor = cipher.encryptor()

    try:
      plaintext_file=open(sys.argv[4],"r") #Opening the plaintext file input for data manipulation/encryption
      ciphertext = encryptor.update(plaintext_file.read()) + encryptor.finalize() #Encrypting the contents of the plaintext with symmetric key algorithm
    except:
        print "This file specified for encryption doesnot exist"
        sys.exit(1)

##################################################################################################################################################
    #following steps define the encryption of symmetric key using the public of the receiver in order to be sent along with the encrypted file above

    try:
        with open(sys.argv[2], "rb") as key_file: #Opening and serializing the destination public key
          public_key_destination=public_key(key_file)
    except:
        print "public key specified doesnot exist, check usage"
        usage()
        sys.exit(1)


    final_key=key+"::::"+iv #concatenating IV and Key to encrypt for transfer
    #encrypting the key and IV to be sent using public key serialized
    cipher_key = public_key_destination.encrypt(final_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


##################################################################################################################################################
    #following steps define signature creation and writing all the contents to ciphertext_file. Using the authentication tag in GCM mode as the value to be signed and verified

    try:
        with open(sys.argv[3], "rb") as key_file:
         private_key_sender=private_key(key_file)
    except:
        print "private key specified doesnot exist, check usage"
        usage()
        sys.exit(1)


    #creating the signature using private key of the sender
    signature = private_key_sender.sign(encryptor.tag, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

    #concatenating all the encrypted data to be sent
    ciphertext_file=ciphertext+"::::::::"+cipher_key+"::::::::"+signature+"::::::::"+encryptor.tag
    ciphertext_file_name=sys.argv[5]
    try:
      os.remove(ciphertext_file_name)
    except:
      print "Creating a file "+ciphertext_file_name+" to write encrypted data into"
    with open(ciphertext_file_name,"w") as cfile:
        cfile.write(ciphertext_file)
    cfile.close()

    print "Encryption complete, file saved as: "+ciphertext_file_name



#beginning of decryption module

def decrypt_verify():  #decryption function to decrypt and verify the files

    try:
      cfile= open(sys.argv[4],"r") #reading the encrypted file and splitting the content to get tokens for decryption
      cipherfile=cfile.read()
    except:
        print "Cipher file doesnot exist,check usage"
        usage()
        sys.exit(1)

    ciphertext = cipherfile.split("::::::::")[0] #actual encrypted file
    cipher_key = cipherfile.split("::::::::")[1] #encrypted key and IV required for decryption
    signature = cipherfile.split("::::::::")[2]  #Signature attached for verification
    tag = cipherfile.split("::::::::")[3]        #tag to be verify the generated signature

    try:
      with open(sys.argv[2], "rb") as key_file:
        private_key_receiver = private_key(key_file)
        #decrypting symmetric key with receiver's private key
        try:
         symmetric_plaintext= private_key_receiver.decrypt(cipher_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
        except:
            print "Cipher file changed, Integrity compromised"
    except:
        print "private key doesnot exist, check usage"
        usage()
        sys.exit(1)




    key=symmetric_plaintext.split("::::")[0] #extracting Key and IV
    iv=symmetric_plaintext.split("::::")[1]


    #decrypting plaintext with symmetric key and IV
    try:
        decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
    except:
        print "Decryption function failed to load modules"


    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext_file_name = sys.argv[5]
    try:
      os.remove(plaintext_file_name)
    except:
        print "Creating a file "+ plaintext_file_name+" to write decrypted text into"
    with open(plaintext_file_name,"w") as pfile:
        pfile.write(plaintext)
    pfile.close()

###################################################################################################################################################
    #veriying signature
    try:
      with open(sys.argv[3], "rb") as key_file:
        public_key_receiver = public_key(key_file)


        try:
         public_key_receiver.verify(signature,tag,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
         print "Signature verified, Integrity Intact"
        except:
            print "Signature Not Correct, File is compromised, Run.........."

    except:
        print "public key doesnot exist, check usage()"
        usage()
        sys.exit(1)

    print "decryption complete, file saved as: "+plaintext_file_name



#main function

def main():

  if (len(sys.argv))!=6:
      usage()

  else:


    if sys.argv[1]=="-e":
         encrypt_sign()
    elif sys.argv[1]=="-d":
         decrypt_verify()
    else:
        print "Wrong Input"
        usage()


main()
