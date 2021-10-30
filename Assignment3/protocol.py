import hashlib
import hmac
import pyDH
import secrets
import Cryptodome
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.diffieHellman = pyDH.DiffieHellman()
        self.publicKey = self.diffieHellman.gen_public_key()
        self.sharedSecret = 'HI689V8W8VPS1LA894FUX5U892'
        self.sessionKey = get_random_bytes(16)
        self.Ra = 0
        self.Rb = 0
        self.Msg1 = None
        self.Msg2 = None

        a = Protocol.EncryptAndProtectMessage(self,bytes('testmsg',encoding='utf-8'), 20)
        x = Protocol.DecryptAndVerifyMessage(self, a, 20)

        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytearray(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()

        self.Ra = secrets.token_hex(128)
        msg = str("CLIENT"+'|'+self.Ra)
        self.Msg1=msg
        return msg

    def GetProtocolReplyMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytes(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()
        
        hM = hashlib.sha3_256()
        hM.update(bytes(str(self.Msg1),encoding="utf-8"))
        prevHash = hM.digest()

        encrypt = Protocol.EncryptAndProtectMessage(self,bytes(str(self.publicKey)+str(prevHash),encoding="utf-8"),self.Ra)
        self.Rb = secrets.token_hex(128)
        msg = str("SERVER"+'|'+self.Rb+'|'+str(encrypt))
        self.Msg2=msg
        return msg

    def GetProtocolAckMessage(self):
        hM = hashlib.sha3_256()
        hM.update(bytes(self.Msg1, encoding="utf-8"))
        hM.update(bytes(self.Msg2, encoding="utf-8"))
        prevHash = hM.digest()

        encrypt = Protocol.EncryptAndProtectMessage(self,bytes(str(self.publicKey)+str(prevHash),encoding="utf-8"),self.Rb)
        msg = str("ACK"+'|'+str(encrypt))
        return msg


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        msg=message.split('|')
        if msg[0]=="CLIENT" or msg[0]=="SERVER" or msg[0]=="ACKNOW":
            return True
        return False

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        publicKey = None
        handshakeProgress = 0
        decoded = message.decode()
        split=decoded.split('|')
        print(split)
        
        if split[0]=="CLIENT":
            self.Msg1=str(message)
            self.Ra = split[1]
            handshakeProgress = 1
        elif split[0]=="SERVER":
            self.Msg2=str(message)
            self.Rb = split[1]
            print("msg2")
            replied=Protocol.DecryptAndVerifyMessage(self, split[2], self.Ra)
            print(replied)
            publicKey=replied[0]
            if Protocol.hashCheck(self,replied[1],1):
                handshakeProgress = 2
            else:
                raise RuntimeError('Failed to authenticate')
        elif split[0]=="ACKNOW":
            acknowledge=Protocol.DecryptAndVerifyMessage(self, split[1], self.Rb)
            print(acknowledge)
            publicKey=acknowledge[0]
            if Protocol.hashCheck(self,acknowledge[1],2):
                handshakeProgress = 3
            else:
                raise RuntimeError('Failed to authenticate')

        if not publicKey==None:
            sessionKey = self.diffieHellman.gen_shared_key(publicKey)
            self.sessionKey = sessionKey
    
        #else: 
            #raise RuntimeError('Failed to authenticate')
             
        return handshakeProgress


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text, R):
        cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce=bytes(R))
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        return str(base64.b64encode(cipher_text)+base64.b64encode(tag), "utf-8")


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text, R):
        #will probs need to check hash for integrity
        try:
            cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce=bytes(R)) #in documentation, this also took in a nonce
            bytestream=bytes(cipher_text,encoding='utf-8')
            tag = base64.b64decode(bytestream[-24:])
            withoutTag = base64.b64decode(bytestream[:-24])
            return cipher.decrypt_and_verify(withoutTag, tag)
        except ValueError:
            print("Tampering in encrypted message was detected!")
        pass

    def hashCheck(self, digest, stage):
        h = hashlib.sha3_256()
        h.update(bytes(str(self.Msg1),encoding="utf-8"))
        if stage == 2:
            h.update(bytes(str(self.Msg2),encoding="utf-8"))
        
        if digest == h.digest():
            return True
        else:
            return False
