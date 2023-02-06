#%%
from random import randint

import requests
from Crypto.Hash import HMAC, SHA3_256, SHA256
from ecpy.curves import Curve, Point

# API_URL = 'http://10.92.55.4:5000'
API_URL = 'http://10.92.52.255:5000/'

stuID = 26906

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code,IKPrivate, IKPub_x, IKPub_y):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKPrivate)+"\n"+"IK.Pub.x: "+str(IKPub_x)+"\n"+"IK.Pub.y: "+str(IKPub_y))
        f.close()

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
    if((response.ok) == False): print(response.json())

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, 'big')
    
def Generate_Keys(n,P):
    private = randint(1,n-2) # both ends are inclusive
    public = private*P
    return private, public

def Generate_Signature(message,private_key,n,P):
    k = randint(1,n-2)
    R = k*P
    r = (R.x)%n
    h = SHA3_256.new((int_to_bytes(r) + int_to_bytes(message)))
    h_int = int.from_bytes(h.digest(), byteorder='big')%n # convert the hash into an integer
    s = (k + private_key*h_int)%n
    return {'H':h_int,'S':s}

def Verify_Signature(signature,public_key,message,n,P):
    V = signature['S']*P - signature['H']*public_key
    v = V.x%n
    h = SHA3_256.new((int_to_bytes(v) + int_to_bytes(message)))
    h_int = bytes_to_int(h.digest())%n # convert the hash into an integer
    print(h_int)
    return h_int == signature['H']

if __name__ == '__main__':
    # Code needs to be run in separate parts due to IKRegVerify requiring the verification code from email
    # So I run parts RUN1, RUN2 consequently without resetting the runtime to not lose the Curve parameters

    RUN1 = 0

    # RUN 1
    if RUN1:
        E = Curve.get_curve('secp256k1')
        n = E.order
        p = E.field
        P = E.generator
        a = E.a
        b = E.b

        # IK PART
        IK_PRIVATE, IK_PUBLIC = Generate_Keys(n,P)
        IK_SIGNATURE = Generate_Signature(stuID,IK_PRIVATE,n,P)
        IKRegReq(IK_SIGNATURE['H'], IK_SIGNATURE['S'], IK_PUBLIC.x, IK_PUBLIC.y)

    # RUN 2
    if not RUN1:
        # IKRegVerify(967779,IK_PRIVATE,IK_PUBLIC.x,IK_PUBLIC.y)

        # SPK PART
        SPK_PRIVATE, SPK_PUBLIC = Generate_Keys(n,P)
        SPK_SIGNATURE = Generate_Signature(bytes_to_int(int_to_bytes(SPK_PUBLIC.x)+int_to_bytes(SPK_PUBLIC.y)),IK_PRIVATE,n,P)
        SPKS_X,SPKS_Y,SPKS_H,SPKS_S = SPKReg(SPK_SIGNATURE['H'], SPK_SIGNATURE['S'], SPK_PUBLIC.x, SPK_PUBLIC.y)

        SPKS_SIGN = {'H': SPKS_H, 'S': SPKS_S}
        SPKS_PUB = Point(SPKS_X,SPKS_Y,E)

        Verify_Signature(SPKS_SIGN, SPKS_PUB, bytes_to_int(int_to_bytes(SPKS_PUB.x)+int_to_bytes(SPKS_PUB.y)),n,P)
        
        # OTK PART
        T = SPK_PRIVATE*SPKS_PUB
        U = b'CuriosityIsTheHMACKeyToCreativity' + int_to_bytes(T.y) + int_to_bytes(T.x)
        KHMAC = SHA3_256.new(U)
        KHMAC_digest = KHMAC.digest()

        OTK_PRIVATE_LIST = []
        for i in range(10):
            OTK_PRIVATE, OTK_PUBLIC = Generate_Keys(n,P)
            OTK_PRIVATE_LIST.append(OTK_PRIVATE)
            OTK_HMAC = HMAC.new(KHMAC_digest,int_to_bytes(OTK_PUBLIC.x) + int_to_bytes(OTK_PUBLIC.y),digestmod=SHA256)
            OTKReg(i,OTK_PUBLIC.x,OTK_PUBLIC.y,str(OTK_HMAC.hexdigest()))

