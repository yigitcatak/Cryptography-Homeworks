#%%

import json
import math
import random
import re
import sys
import time
import warnings
from random import randint, seed

import requests
import sympy
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA3_256, SHA256
from Crypto.Util.Padding import pad, unpad
from ecpy.curves import Curve, Point

API_URL = 'http://10.92.52.255:5000/'

stuID = 26906
stuIDB = 2014
E = Curve.get_curve('secp256k1')

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, 'big')

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1,n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (sA*h + k) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, E)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

############## The new functions of phase 2 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())


if __name__ == '__main__':
    IK_PRIVATE = 93841414515250086403169993766023098632634572242058166962096587960761856572461
    OTK_PRIVATE_LIST = [25996206826748945179986055808701717480259345734984844639328322347954736314124,
                        16112472380129272087581549693008825993697413531039145806650980824294847189838,
                        48345831976599106275776439678437787835517021803943266885421686013679616412272,
                        80269638015588846204093497224902139068552029920388306453551120766448541089626,
                        68808880758996309412733523252539627540606038976748725567043879775292093663363,
                        81311889515338995347934676525317988031836667535006315325426255930648784565518,
                        103785570521511146221415955573230751844688506577622998683391344065817336435437,
                        82988513865464362944854385684010408994304427726700712506257337555879919155222,
                        52821756294282512064531401033983276999323460153139308198604113516041292846985,
                        87688417602178365341498966461689727385650271830743624174541113552897662865575]

    signID = SignGen(int_to_bytes(stuID),E,IK_PRIVATE)
    signID = {'H': signID[0], 'S': signID[1]}
    
    # PseudoSendMsg(signID['H'],signID['S'])
    Messages = []
    Outputs = []
    while True:
        resp = ReqMsg(signID['H'],signID['S'])
        if not resp:
            break
        EK = Point(resp[-2],resp[-1],E)
        Messages.append({'IDB':resp[0], 'OTKID':resp[1], 'MSGID':resp[2], 'MSG':resp[3], 'EK':EK})
    
    if len(Messages) != 0:
        first = True
        for mid, Message in enumerate(Messages):
            MSG = int_to_bytes(Message['MSG'])        
            if first:
                T = OTK_PRIVATE_LIST[Message['OTKID']]*Message['EK']
                U = int_to_bytes(T.x) + int_to_bytes(T.y) + b'ToBeOrNotToBe'
                KS = SHA3_256.new(U).digest()
                first = False

            KENC = SHA3_256.new(KS + b'YouTalkingToMe').digest()
            KHMAC = SHA3_256.new(KS + KENC +  b'YouCannotHandleTheTruth').digest()
            KS = SHA3_256.new(KENC + KHMAC + b'MayTheForceBeWithYou').digest()

            mac = MSG[-32:]
            nonce = MSG[:8]
            ctext = MSG[8:-32]

            hmac = HMAC.new(KHMAC,ctext,digestmod=SHA256).digest()
            cipher = AES.new(KENC,mode=AES.MODE_CTR,nonce=nonce)

            if hmac == mac:
                ptext = cipher.decrypt(ctext).decode()
                Outputs.append(f"Message {Message['MSGID']} - {ptext} - Read")

            else:
                print(f'Invalid HMAC on message {mid+1}')
                ptext = 'INVALIDHMAC'
                
            # Checker(stuID, Message['IDB'], mid+1, ptext)
        
    # deleted = ReqDelMsg(signID['H'],signID['S'])
    # if not deleted:
    #     deleted = []
    
    # for m in Outputs:
    #     idx = int(m[8])
    #     print(m[:m.find('-')]+"- Was deleted by sender - X") if idx in deleted else print(m)

    for m in Outputs:
        idx = int(m[8])
        print(m)