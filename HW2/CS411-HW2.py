#%%
import os
import random
from math import gcd

from client import *
from Crypto.Cipher import Salsa20
from hw2_helper import *
from lfsr import BM, LFSR, FindPeriod
from myntl import egcd, modinv
from math import ceil

FILE = "server_responses.txt"
CWD = os.getcwd()
TEXT_PATH = os.path.join(CWD,FILE)

if not os.path.isfile(TEXT_PATH):
    with open(TEXT_PATH, "w+") as file:
        n,t = getQ1()
        e,c = getQ2()
        server_response = str(n) + " " + str(t) + "\n" + str(e) + " " + str(c)
        file.write(server_response)
        
else:
    with open(TEXT_PATH) as file:
        n,t = (int(i) for i in file.readline().split())
        e,c = (int(i) for i in file.readline().split())

def findMultiplicativeGroup(n):
    result = set()
    for i in range(1,n):
        if gcd(i,n) == 1:
            result.add(i)
    return result

def findSmallestGenerator(in_group, in_n):
    for i in in_group:
        temp_group = {i}
        for exponent in range(2,in_n):    
            num = (i**exponent)%in_n
            if (num in in_group) and (num not in temp_group):
                temp_group.add(num)
            else:
                break
        if len(temp_group) == len(in_group):
            return i

def findSubgroup(in_group, in_n, in_t):
    for i in in_group:
        if (i**t)%n == 1:
            temp_group = {i}
            for exponent in range(2,in_n):
                num = (i**exponent)%in_n
                if (num in in_group) and (num not in temp_group):
                    temp_group.add(num)
                else:
                    break
            if len(temp_group) == in_t:
                return i, temp_group

def solveLinearCongurence(n,a,b):
    # reffered to the video https://www.youtube.com/watch?v=Lrr_QJbxoHQ for solving linear congruences
    gcd_a_n, x, _ = egcd(a,n)

    if (b%gcd_a_n):
        print("There is no solution.\n")
        return

    # then we have
    # ax' + yn = gcd(a,n), then
    # ax' = gcd(a,n) mod n => a(x' * b/gcd(a,n)) = b mod n
    # then (x' * b/gcd(a,n)) is our initial x value
    
    multiplier = b//gcd_a_n
    x = (x*multiplier)

    # the EEA might give negative values for x and y. They are not incorrect
    # but for linear congruence we seek x values between 0 and n-1
    if x < 0:
        x += n
    
    # there are gcd(a,n) number of solutions, we can increase this x
    # with increments of n/gcd(a,n) in range of n for all possible x values 

    print("The solutions are:")
    for i in range(gcd_a_n):
        print((x + i*n//gcd_a_n)%n)
    print()

def Q1(checkFromServer=False):    
    zmultmodn = findMultiplicativeGroup(n)
    print(f"the order of Z_{n} multiplicative group is {len(zmultmodn)} and it consists of elements:\n{zmultmodn}\nChecking Q1a:")
    if checkFromServer: checkQ1a(len(zmultmodn))

    generator = findSmallestGenerator(zmultmodn, n)

    print(f"\n{generator} is a generator for Z_{n} multiplicative group\nChecking Q1b:")
    if checkFromServer: checkQ1b(generator)

    subgroup_generator, subgroup = findSubgroup(zmultmodn, n, t)

    print(f"\nThe generator {subgroup_generator} yields subgroup of order {t}, the group is:\n{subgroup}\nChecking Q1c:")
    if checkFromServer: checkQ1c(subgroup_generator)

def Q2(checkFromServer=False):
    p = 129711420978537746088867309342132426785901989689874594485896371555019986573705426172788805726178509467748040679168734095884433597017604012172054368990172572715857537355524013819947862920969421702067385445122242673064958991968666138544380365520456029952414962028711806175784928131826127885820644091951344318387
    q = 174066672405085972657808881778978520582809763235147358374332409966322987290745416405220414323004782906757362579157117914494927198442645581197584273451379119673753279114693557694861941678350357667191083878100828920198503774539271289263633646647364198130180304138099281532660260760636194367337370132530987351081
    n = p*q
    fi = (p-1)*(q-1) #since p and q are prime (checked from an online prime checker)
    d = modinv(e,fi)
    m = pow(c,d,n)

    byte_result = m.to_bytes(ceil(m.bit_length()/8), byteorder="big")
    string_result = byte_result.decode()
    print(f"The resulting message is:\n{string_result}\nCheckingQ2:")

    if checkFromServer:
        checkQ2(string_result)

def Q3():
    ctexts = [b"Vbq\x8a\xe3\xb7Rgl-\x14\x8bNS\xeb\x01\xbd\xdf\x1f\x14\x84{\xdanX,\xa5\x98RM\x98\r\xd7\x1e\x9dO\x14\xa7\x8cX\xcb\xad\xf2\xc9\x1f\xc1]\xef\x908I\xe0\xcf\x10%.ulh\xe7\xd6\x9d<\xb9a\xda\xb0\xa2d\xe9\x18\xef9\x99ttP\x9blw\x0e\xe7\xd6\xbb1\xf4?\x16kf\x87\x19\xbe\x94O\xe8\x1d\x08\xe4\xff)\x99']\xda\x191=|H", b"\eda\x01q+]\x8c\x06[\xa2/\xb8\xcaX\x1f\x8f:\xc97\x0f)\xa5\x84Y\t\xdc\x07\xd2L\xb3V\x14\xad\x8bU\x99\xa3\xf2\x9dK\xc8V\xab\xdd\nS\xe9\xcf\x05$r,\t<\x9e\xd0\x9b<\xbcx\x99\xaf\xed7\xf9\x13\xff9\x88r \\\x9b}>\x1d\xeb", b"ea,\x14\x88NW\xbfh\xb9\xcdX\x0f\x83}\xc0cX5\xa5\x9e\x1e^\xd0\x03\xc5\x1e\xa3U@\xa1\x85H\xc0"]

    key = 14656892184006070584
    key =key.to_bytes(32, byteorder='big')
    ctext_nonce = ctexts[0][:8]

    print("The first cipher text has no corruption and it can be decrypted directly. We use this nonce for other cipher texts as well. However, we don't know the length of the corrupted nonce for those, so I try to strip first 0,1,2,..,8 bytes of the message which is the corrupted nonce.\n")
    for idx, ctext in enumerate(ctexts):
        for i in range(9):
            try:
                cipher = Salsa20.new(key, nonce=ctext_nonce)
                dtext = cipher.decrypt(ctext[i:])
                print(f"Decoded text {idx+1}: {dtext.decode('UTF-8')}\n")
            except:
                pass

def Q4():
    n_values = [1593089977489628213419978935847037520292814625191902216371975, 1604381279648013370121337611949677864830039917668320704906912, 591375382219300240363628802132113226233154663323164696317092, 72223241701063812950018534557861370515090379790101401906496]
    a_values = [1085484459548069946264190994325065981547479490357385174198606, 363513302982222769246854729203529628172715297372073676369299, 1143601365013264416361441429727110867366620091483828932889862,798442746309714903219853299207137826650460450190001016593820]
    b_values = [953189746439821656094084356255725844528749341834716784445794, 1306899432917281278335140993361301678049317527759257978568241, 368444135753187037947211618249879699701466381631559610698826, 263077027284763417836483401088884721142505761791336585685868]

    for n,a,b in zip(n_values,a_values,b_values):
        solveLinearCongurence(n,a,b)

def Q5():
    LCS = [[L, [0 for i in range(L+1)], [0 for i in range(L)]] for L in (6,6,5)]
    LCS[0][1][6] = LCS[0][1][5] = LCS[0][1][4] = LCS[0][1][1] = LCS[0][1][0] = 1
    LCS[1][1][6] = LCS[1][1][2] = LCS[1][1][0] = 1
    LCS[2][1][5] = LCS[2][1][3] = LCS[2][1][0] = 1
    length = 256

    for idx,[L,C,S] in enumerate(LCS):
        max_period = 2**L-1
        print(f"For polynomial {idx+1}, maximum period is {max_period}")
        for i in range(0,L):            # for random initial state
            S[i] = random.randint(0, 1) 
        # print ("Initial state: ", S) 

        keystream = [0]*length
        for i in range(0,length):
            keystream[i] = LFSR(C, S)
        
        period = FindPeriod(keystream)
        print(f"Actual period is {period}, the polynomial{' ' if period == max_period else ' does not '}generate maximum period sequence\n")

def Q6():
    streams = [[0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0], [0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1], [1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1]]
    for idx, stream in enumerate(streams):
        L, _ = BM(stream)
        expected = len(stream)/2 + 2/9
        print(f"For stream {idx+1} expected linear complexity is {expected}, the actual linear complexity is {L}\n")

def Q7():
    ctext = [1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]
    
    # "Utku Ay" does not work as it is too short to have an insight on the polynomial
    text_piece = ASCII2bin('Atil Utku Ay')

    # as we are working from end-to-start I just reversed the known text and cipher text
    # as LFSR is a continuous stream cipher this wont effect the result
    ctext.reverse()
    text_piece.reverse()

    # for the known part of the key we just XOR the corresponding parts
    keystream = [text_piece[i]^ctext[i] for i in range(len(text_piece))]


    L, polynomial = BM(keystream)
    print(f"Connection polynomial of the key is:\n{polynomial}\n")

    for i in range(len(text_piece), len(ctext)):
        new_bit = 0
        for j in range(1,L+1):
            new_bit += keystream[-j] * polynomial[j]
        keystream.append(new_bit%2)

    ptext = [keystream[i]^ctext[i] for i in range(len(ctext))]
    ptext.reverse()

    print(f"Decrypted message is:\n{bin2ASCII(ptext)}")

if __name__ == '__main__':
    Q6()
