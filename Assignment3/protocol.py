import hashlib
import hmac
import pyDH
import secrets
import Cryptodome
from Cryptodome.Cipher import AES

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.diffieHellman = pyDH.DiffieHellman()
        self.publicKey = self.diffieHellman.gen_public_key()
        self.sharedSecret = 'HI689V8W8VPS1LA894FUX5U892'
        self.sessionKey = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        initialize = ["CLIENT"]
        initialize.append(secrets.token_bytes(128))
        return initialize


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        if message[0]=="CLIENT":
            return True
        return False

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, tag):
        decryptedMessage = DecryptAndVerifyMessage(self, message, tag)
        
        # need to check rest of message in order to authenticate, idk how


        # 256 characters in libary generated diffie hellmans
        if len(decryptedMessage) > 256 :
            publicKey = "this is temp string, to be extracted from message"
            sessionKey = self.diffieHellman.gen_shared_key(publicKey)
            SetSessionKey(self, sessionKey)
    
        else: 
            raise RuntimeError('Failed to authenticate')
             
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self.sessionKey = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        if self.sessionKey == None:
            cipher = AES.new(hash(self.sharedSecret), AES.MODE_EAX)
        else:
            cipher = AES.new(self.sessionKey, AES.MODE_EAX)
            
        plainBinary = ''.join(format(ord(i), '08b') for i in plain_text)
        cipher_text, tag = cipher.encrypt_and_digest(plainBinary)
        return cipher_text, tag


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text, tag):
        #will probs need to check hash for integrity
        try:
            if self.sessionKey == None:
                cipher = AES.new(hash(self.sharedSecret), AES.MODE_EAX) #in documentation, this also took in a nonce
            else:
                cipher = AES.new(self.sessionKey, AES.MODE_EAX) #in documentation, this also took in a nonce
                
            binary = cipher.decrypt_and_verify(cipher_text, tag)
            plain_text = BinaryToString(binary)
            return plain_text
        except ValueError:
            print("Tampering in encripted message was detected!")
        pass


    # Takes in a value in binary and returns that value as a regular string
    def BinaryToString(binary):
        stringOut = ''
        for i in range(0, len(binary), 7):
            binarySection = binary[i:i + 7]
            decimalVal = int(binarySection, 2)
            stringOut = stringOut + chr(decimalVal)
        
        return stringOut
