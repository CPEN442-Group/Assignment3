import hashlib
import pyDH
import secrets
from Cryptodome.Cipher import AES
import base64

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.diffieHellman = pyDH.DiffieHellman()
        self.privateKey = self.diffieHellman.gen_public_key()
        self.publicKey = None
        self.sharedSecret = 'HI689V8W8VPS1LA894FUX5U892'
        self.sessionKey = None
        self.Ra = 0
        self.Rb = 0
        self.Msg1 = None
        self.Msg2 = None
        pass

    # Generates CLT - initial message
    def GetProtocolInitiationMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytearray(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()
        
        self.Ra = secrets.token_hex(128)
        msg = str("CLIENT"+'|'+self.Ra)
        self.Msg1=msg
        return msg

    # Generates SVR
    def GetProtocolReplyMessage(self, sharedSecret):
        h = hashlib.sha3_256()
        h.update(bytes(sharedSecret, 'utf-8'))
        self.sessionKey = h.digest()
        
        hM = hashlib.sha3_256()
        hM.update(bytes(str(self.Msg1),encoding="utf-8"))
        prevHash = hM.digest()
        
        encrypt = Protocol.EncryptAndProtectMessage(self,bytes(str(self.privateKey)+'|'+str(prevHash),encoding="utf-8"),self.Ra)
        self.Rb = secrets.token_hex(128)
        msg = str("SERVER"+'|'+self.Rb+'|'+encrypt)
        self.Msg2=msg
        return msg

    # Generates ACK
    def GetProtocolAckMessage(self):
        hM = hashlib.sha3_256()
        hM.update(bytes(str(self.Msg1), encoding="utf-8"))
        hM.update(bytes(str(self.Msg2), encoding="utf-8"))
        prevHash = hM.digest()

        encrypt = Protocol.EncryptAndProtectMessage(self,bytes(str(self.privateKey)+'|'+str(prevHash),encoding="utf-8"),self.Rb)
        msg = str("ACK"+'|'+encrypt)
        return msg


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        try:
            decode=message.decode()
            msg=decode.split('|')
            if msg[0]=="CLIENT" or msg[0]=="SERVER" or msg[0]=="ACK":
                return True
            else:
                return False
        except:
            return False

    # Processing handshake protocol
    def ProcessReceivedProtocolMessage(self, message):
        handshakeProgress = 0
        decoded = message.decode()
        split=decoded.split('|')
        
        if split[0]=="CLIENT":
            self.Msg1=decoded
            self.Ra = split[1]
            handshakeProgress = 1

        elif split[0]=="SERVER":
            self.Msg2=decoded
            self.Rb = split[1]
            decrypt=Protocol.DecryptAndVerifyMessage(self, split[2], self.Ra).split('|')
            self.publicKey=int(decrypt[0])
            if Protocol.hashCheck(self,decrypt[1],1):
                handshakeProgress = 2
            else:
                raise RuntimeError('Hash failed to authenticate')

        elif split[0]=="ACK":
            decrypt=Protocol.DecryptAndVerifyMessage(self, split[1], self.Rb).split('|')
            self.publicKey=int(decrypt[0])
            if Protocol.hashCheck(self,decrypt[1],2):
                handshakeProgress = 3
            else:
                raise RuntimeError('Hash failed to authenticate')
    
        else: 
            raise RuntimeError('Failed to authenticate')
        return handshakeProgress

    # Sets 256-bit session key using DH shared key
    def SetSessionKey(self):
        dh = self.diffieHellman.gen_shared_key(self.publicKey)
        h = hashlib.sha3_256()
        h.update(bytes(dh,encoding='utf-8'))
        self.sessionKey = h.digest()
        return

    # Encrypting messages
    def EncryptAndProtectMessage(self, plain_text, R):
        cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce=bytes(R,encoding='utf-8'))
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        return str(base64.b64encode(cipher_text)+base64.b64encode(tag), "utf-8")

    # Decrypting and verifying messages
    def DecryptAndVerifyMessage(self, cipher_text, R):
        #will probs need to check hash for integrity
        try:
            cipher = AES.new(self.sessionKey, AES.MODE_EAX, nonce=bytes(R,encoding='utf-8'))
            bytestream=bytes(cipher_text,encoding='utf-8')
            tag = base64.b64decode(bytestream[-24:])
            withoutTag = base64.b64decode(bytestream[:-24])
            plaintext = cipher.decrypt_and_verify(withoutTag, tag)
            return plaintext.decode()
        except ValueError:
            print("Tampering in encrypted message was detected!")
        pass

    # Verify the hashes of the handshake
    def hashCheck(self, hash, stage):
        h = hashlib.sha3_256()
        h.update(bytes(str(self.Msg1),encoding="utf-8"))
        if stage == 2:
            h.update(bytes(str(self.Msg2),encoding="utf-8"))
        digest = str(h.digest())
        
        if hash == digest:
            return True
        else:
            return False
