#%%
from random import randint

import requests
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA3_256, SHA256
from ecpy.curves import Curve, Point

API_URL = 'http://10.92.52.255:5000/'
E = Curve.get_curve('secp256k1')
stuID = 26906
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,8985629203225767185464920094198364255740987346743912071843303975587695337619,E)
SPKS_PUB = Point(85040781858568445399879179922879835942032506645887434621361669108644661638219,46354559534391251764410704735456214670494836161052287022185178295305851364841,E)
IK_PRIVATE = 93841414515250086403169993766023098632634572242058166962096587960761856572461
SPK_PRIVATE = 87492722728285515468059537487866416461838082554623418415108614170332428151274
OTK_PRIVATE_LIST = []

try:
    with open('OTKList.txt') as f:
        for otk in f:
            OTK_PRIVATE_LIST.append(int(otk))
except:
    print('----------\nCould not find the OTK list in the directory. Please provide OTK list.\n----------\n')


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, 'big')

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
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

def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if(response.ok == False):
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())

def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())
    
def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

def Send(Messages: list, stuIDB: int):
    signIDB = SignGen(int_to_bytes(stuIDB),E,IK_PRIVATE)
    signIDB = {'H': signIDB[0], 'S': signIDB[1]}

    OTKB = reqOTKB(stuID,stuIDB,signIDB['H'],signIDB['S'])
    OTKIDB = OTKB[0]
    if OTKIDB == -1:
        print("The target has no OTK left. Cannot send the message.")
        return
    OTKB = Point(OTKB[1],OTKB[2],E)
    
    EK_PRIVATE, EK_PUBLIC = KeyGen(E)
    T = EK_PRIVATE*OTKB
    U = int_to_bytes(T.x) + int_to_bytes(T.y) + b'ToBeOrNotToBe'
    KS = SHA3_256.new(U).digest()

    for i, message in enumerate(Messages):
        MSG = message.encode()
        KENC = SHA3_256.new(KS + b'YouTalkingToMe').digest()
        KHMAC = SHA3_256.new(KS + KENC +  b'YouCannotHandleTheTruth').digest()
        KS = SHA3_256.new(KENC + KHMAC + b'MayTheForceBeWithYou').digest()

        cipher = AES.new(KENC,mode=AES.MODE_CTR)
        ctext = cipher.encrypt(MSG)
        hmac = HMAC.new(KHMAC,ctext,digestmod=SHA256).digest()
        MSG = bytes_to_int(cipher.nonce + ctext + hmac)

        SendMsg(stuID, stuIDB, OTKIDB, i+1, MSG, EK_PUBLIC.x, EK_PUBLIC.y)

def Read():
    signID = SignGen(int_to_bytes(stuID),E,IK_PRIVATE)
    signID = {'H': signID[0], 'S': signID[1]}
    
    incomingMessages = []
    
    Ptexts = []
    while True:
        resp = ReqMsg(signID['H'],signID['S'])
        if not resp:
            break
        EK = Point(resp[-2],resp[-1],E)
        incomingMessages.append({'IDB':resp[0], 'OTKID':resp[1], 'MSGID':resp[2], 'MSG':resp[3], 'EK':EK})
    
    while len(incomingMessages) != 0:
        Outputs = []
        first = True
        previous_OTKID = incomingMessages[0]['OTKID']
        for mid, Message in enumerate(incomingMessages):
            OTKID = Message['OTKID']
            if previous_OTKID == OTKID:
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
                    Ptexts.append(ptext)
                    Outputs.append(f"From: {Message['IDB']} - Message {Message['MSGID']} - {ptext} - Read")

                else:
                    print(f'Invalid HMAC for message {mid+1}')

            else:
                incomingMessages = incomingMessages[mid:]
                break
            
            if mid == len(incomingMessages)-1:
                incomingMessages = []
        # deleted = ReqDelMsg(signID['H'],signID['S'])
        # if not deleted:
        #     deleted = []
        
        for m in Outputs:
        #     print(m[:m.find('-')]+"- Was deleted by sender - X") if int(m[8]) in deleted else print(m)
            print(m)

    return Ptexts

def checkOTK():
    signID = SignGen(int_to_bytes(stuID),E,IK_PRIVATE)
    signID = {'H':signID[0],'S':signID[1]}
    remainingOTK = Status(stuID, signID['H'], signID['S'])[1]

    if remainingOTK > 1:
        return
    
    T = SPK_PRIVATE*SPKS_PUB
    U = b'CuriosityIsTheHMACKeyToCreativity' + int_to_bytes(T.y) + int_to_bytes(T.x)
    KHMAC = SHA3_256.new(U)
    KHMAC_digest = KHMAC.digest()

    global OTK_PRIVATE_LIST
    for i in range(10):
        OTK_PRIVATE, OTK_PUBLIC = KeyGen(E)
        OTK_PRIVATE_LIST[i] = OTK_PRIVATE
        OTK_HMAC = HMAC.new(KHMAC_digest,int_to_bytes(OTK_PUBLIC.x) + int_to_bytes(OTK_PUBLIC.y),digestmod=SHA256)
        OTKReg(i,OTK_PUBLIC.x,OTK_PUBLIC.y,str(OTK_HMAC.hexdigest()))
    
    with open("OTKList.txt", "w+") as f:
        for i,otk in enumerate(OTK_PRIVATE_LIST):
            f.write(str(otk) + "\n") if i != 9 else f.write(str(otk))

if __name__ == '__main__':
    PHASE3_RUN = 1 # this is the run explained in the document, get 5 messages from pseudo client
    # decrypt them, and send them back to the pseudo client by encrypting them again.
    # the server did not give me the OTK of pseudo client with id 26045 therefore I could not try this 

    SEND_RUN = 0 # set 1 if you want to send messages
    TRIAL_RUN = 0 # set 1 to send message to self and read them back 

    # Setting all of the above to 0 means, only reading the inbox.
    # The priority is PHASE3 > TRIAL > SEND if more than one of them are set to 1
     
    RecieverID = 26906 # set to the id of the person you want to send message to
    Messages = ['Good morning Vietnam','Let\'s see Paul Allen\'s card'] # set the messages to send

    print("-----\nINITIALLY READING THE INBOX\n------\n")
    Read()
    checkOTK() # Renew OTK if needed after reading the inbox with the previous OTK's
        
    if PHASE3_RUN:
        signID = SignGen(int_to_bytes(stuID),E,IK_PRIVATE)
        signID = {'H':signID[0],'S':signID[1]}
        PseudoSendMsgPH3(signID['H'],signID['S'])
        ptexts = Read()
        Send(ptexts,26045)

    elif TRIAL_RUN:
        Send(Messages,stuID)
        Read()

    elif SEND_RUN:
        Send(Messages,RecieverID)
    

    

   

     
        

    