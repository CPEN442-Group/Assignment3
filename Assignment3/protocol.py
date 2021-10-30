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
        self.Msg1 = None
        self.Msg2 = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytearray(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()
        msg = str("CLIENT"+'|'+secrets.token_hex(128))
        self.Msg1=msg
        return msg

    def GetProtocolReplyMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytes(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()
        
        hM = hashlib.sha3_256()
        hM.update(bytes(str(self.Msg1),encoding="utf-8"))
        prevHash = hM.digest()

        encrypt, tag = Protocol.EncryptAndProtectMessage(self,bytes(str(self.publicKey)+str(prevHash),encoding="utf-8"))
        msg = str("SERVER"+'|'+secrets.token_hex(128)+'|'+str(encrypt)+str(tag))
        self.Msg2=msg
        return msg

    def GetProtocolAckMessage(self):
        h = hashlib.sha3_256()
        h.update(bytearray("CLIENT",Ra, encoding="utf-8"))
        ackMsg = bytearray(self.publicKey,encoding="utf-8")
        dh=Protocol.EncryptAndProtectMessage()
        helps = bytearray("ACKNOW",1, encoding="utf-8")
        self.sessionKey = h.digest()
        msg = str('sdf')
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
            Ra = split[1]
            handshakeProgress = 1
        elif split[0]=="SERVER":
            self.Msg2=str(message)
            Rb = split[1]
            e = split[2]
            print("msg2")
            print(e)
            print(len(e))
            replied=Protocol.DecryptAndVerifyMessage(self, e)
            print(replied)
            publicKey=replied[0]
            handshakeProgress = 2
        elif split[0]=="ACKNOW":
            acknowledge=Protocol.DecryptAndVerifyMessage(self, bytes(split[1], encoding="utf-8"))
            print(acknowledge)
            publicKey=acknowledge[0]
            handshakeProgress = 3

        if not publicKey==None:
            sessionKey = self.diffieHellman.gen_shared_key(publicKey)
            self.sessionKey = sessionKey
    
        #else: 
            #raise RuntimeError('Failed to authenticate')
             
        return handshakeProgress


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher = AES.new(self.sessionKey, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        return cipher_text, tag


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        #will probs need to check hash for integrity
        try:
            cipher = AES.new(self.sessionKey, AES.MODE_EAX) #in documentation, this also took in a nonce
            withoutTag = cipher_text[0:len(cipher_text)-129]
            plain_text = cipher.decrypt_and_verify(withoutTag, cipher_text[len(cipher_text)-129:])
            return plain_text
        except ValueError:
            print("Tampering in encrypted message was detected!")
        pass
