#%%
from math import ceil, gcd, sqrt

from client import *

def polyMult(lhs,rhs):
    mask = 1
    index = 0 #determines the ammount of shift that rhs will be shifted to left, based on 1 bits in lhs
    result = 0 #holds the result as, each shifted rhs will be xor'ed

    while mask <= lhs: # mask goes 0b1, 0b10, 0b100... until it is larger than lhs, it is used to extract 1 bits from lhs
        if  lhs & mask: # if lhs has 1 at corresponding place, shift the rhs and xor with result
            temp = rhs<<index
            result ^= temp
        mask <<= 1 # mask goes to 1 left bit
        index += 1 # shift ammount increases by 1
    return result

def polyMod(pol,irreducable):
    # xor the irreducable polynomial to polynomial after aligning the msb until polynomial is smaller than irreducable polynomial
    result = pol
    diff = len(bin(result))-len(bin(irreducable)) # diff is the shift ammount to align the msb of divisor with msb of dividend
    while( diff >= 0 ): 
        result ^= irreducable<<diff 
        diff = len(bin(result))-len(bin(irreducable))
    return result

def fermatFactorization(N):
    a = ceil(sqrt(N))
    b = (a**2) - N
    c = int(sqrt(b))
    while b != c**2:
        a += 1
        b = (a**2) - N
        c = int(sqrt(b))

    return a - c, a + c

def Q1():
    N = 14160376831985083549234691952615806088754482769313863972472612104960426897223528465771355471579374406630645418210046457006222595114565610230771399642073008939064571341163391040192895053667746239198745313836608357861688352973345896714893493445912599660303023771086463444245877244662588475490852139709576652071347040782452020420571773050781132633528534621842646272347587344930762951115906409730066558110915658602904086152356440870165207911781076319159782794658036524692436267278201087720505491720755129001866266643708208179209558133605991939687875289929389527569467618218808022773618095749432994955099002138061774558092646935053922768729867596344560354854024333693063848315568843274016677634235943265653870168403483754828778660331273571374962669367723145859407420437087211873179386669565722950274706684709564825917176846099470175848587712359262011453691289856193406245598805109425265282471927598683177731795099636499428783962103265346384863380645563783957116490551095371939941953588841421901208018208833231980963252778549870359034986607401895073749621109530739274084626457126786909062587418357842878093562018076560481599295590002481431272398795041334444497078057214818284076399718097402714878381631253086537958945383846515538826876788531288766825879748890645117613533585994704646456047742249832303552280560598950442935275040981664802396857172617709467797511943183885432902060866416575711977772297223391851636143412166880420086696224346267661926864577871074351112573238283297717693120212428566507110945526676138784819788038239839295288788351687768791008155514660231443432484340203637725314815951740765116548061295612618198058823576843639508119932329130553908867479055715564386028123392718092251110077019826654081948597242333738564418061676295146137851144050784468238754208055080766136851080662924281661590293015860041945804754733697510953608299395441403
    C = 6964000134802147490350421365650336249614250610865941864507560530973065829363013742586720564552761485372116221740627172129123876523265935559212398148078283338483855884374390808303815665061687242251596246200216973015491595396418311911498012690876633098536884830950045033940873472961361944443087691593107828862821646570032433642983137001852284845829650930647062230124067089431359423080345777147816524499368041933760389488812347842387454340351987432497450711320078300294448658548685160053953562838653141801302708015723513455630185668900982623299071334073972206896315094654233704852582483630519657086758386996034282108495983647800489173557906086552456716216042967828046145491119906240052603113568412111123995516281289156205173721081926194326415619996714900950517971362831818945544753717887534879164670744808319717216154781106605434942135917537990413956682184006665259542413721048288165850192732549204068618353559752841030622793211811546498498416331840835131156082144938676253315415796019426308810557107725216135397364965385028974827442762669961840515952862589707634652185583315205043783377926870982096766350787995676580790658222090464434721501852708698323447101795557300364436799578803807748130751797841330640652950406091265871346916787635907157418424516138771191157069377784992022861611028548265664755868362046368995908027874449613065707583578153986732928925323015151853338913936042198087258685083559185030411159644723900086245429733121433845958021799786535702133974611668238336
    E = (2**4)+1

    for M in range(2**288,2**289): # all possible M with 289 bits
        if pow(M,E,N) == C:
            message = M
            break
    
    print(f"289 bit number {message} has the same encryption as C with given RSA settings.")

def Q2():
    N = 735129733350600300814682820983363975841858401155438497255664794289823750303771869563783060904740656108396832861631223213759233199110153841037374050058977286914202841273524024666932250131821113376668815406723621016490979772825337454765842227937701790973178644581429373241485573097140173355071014592912476993973876358900848501647208271118220494126859489227794428441209121779400263427064528800044153594488608641089810344852811969047683323752216047087315762593265636128466350649798266807305401826019476523383574373865654916089798354741168921810503521914845585839161180821237530439632455643648718893847945602507596343025039916399868955525098511955168845334399609780438491582190893008973851423386317328091461841967101793387569401290989098810214189082780241178398539863285659421612567764560272257730862326168958364031351936876932865703535175597367552038394861003656869677510780585595075450570568618061324321406580734938998169197647023586630354046716320331115546825940635140424868018161440043319003351900977331129699978699948137567053016132949764669941675005253460547841482625174892031076638216262945295769084071268327053819352242156952428409005165677559548048829999259603172407376651982303486619116704252671413990026284868294201399181512043
    CP = 591585661179913908292670964497762439966067617632980318594933696993454439728774695673398116279819100780981035776904828340000286556561821690365937795767595578460020372779099849512212679341203336712606691026980784826758612415894186878559418781933556513172143678225888892413399407357572102187313811291121304928928848821740914239643286098598943861830177312939795889893467307582185899931290683200944769576636703683519903565708396786917226998954212438208550716658336081133840312436400158765503544052687056167181841283624622810770703450396047554977193850903901459806510612970231465678503924692665502872536500180880428444652182260677241127037607744405052492742074626162505690986835662409717998630436892609085891138004339602274790886677062920378513594058185353516270486167595057731308599477294190461449818277150803142015005367485865449897543408948648598768730426058899226212982674326317239306732825540115470519539729209054092010428475270982133241739755670905018636775489391024836583829979747436647847343118308007690487133027090643538988141634837671142574166059246803646505989258216228280398544311438792645908159200659488745926355055587928710053702116250352855728835609501615125001498450195370742144016227930442188681846248774022591908284395554
    CM = 410549325685366799284798358668331291049211237703447489321746464354090480951066742200309912524869634695769764148842963115769175527179769353501136785040366302701836605559269222653839509896223034315989474752525422032311356077141993653194048634554747064603617789881601934904375748720866525993835837380575119329831703593942313434602973137707915466599022298281760026130881260276637144571320608488322550304670024203670226128476075072338279764675774256431888736850559740563151465682499215963629918224101757068211315022934434916282345252224165558403932898552995551505591198395331625457165173901358070740812251352212374898226752191458989544999183050305396079595170576363831967410596235893058231852520802407515041647925479992058184613103289709752618729186509661786057001647083804585301703801272797236111687348907977621232083642431914363895266519463459112358271172160273751026080398345460929751476512586349360905588246751625224080678692961596943056437462453579785432258654674275520068227719175943507656108554707552928863240951458193510571735005767226590398204791730466993980158501690130104327829589781448607958503898902133445000532521723138230966914652700465728532524467483612403840506027543892612439531633794667013713638856396514285792898762678
    E = 65537

    P = gcd(N,CP) # N is p*q, CP is k*p, then gcd(N,CP) is p
    Q = N//P
    FI = (P-1)*(Q-1)
    D = pow(E,-1,FI) # modular multiplicative inverse
    
    M = pow(CM,D,N)

    byte_result = M.to_bytes(ceil(M.bit_length()/8), byteorder='little')
    M = byte_result.decode()
    print(M)

def Q3():
    pass

def Q4():
    N = 15220196297956469159
    C = 6092243189299681137
    E = (2**16)+1
    P, Q = fermatFactorization(N)
    FI = (P-1)*(Q-1)
    D = pow(E,-1,FI) # modular multiplicative inverse
    M = pow(C,D,N)

    print(f"Factors of N are P: {P}, Q: {Q}")
    byte_result = M.to_bytes(ceil(M.bit_length()/8), byteorder='little')
    M = byte_result.decode()
    print(f"The message is \"{M}\"")


def Q5(checkFromServer=False):
    P = 0b100011011
    A = 0b00110011
    B = 0b10010111

    print(f"Polynomials are a: {'0'*(10-len(bin(A))) + bin(A)[2:]}, b: {'0'*(10-len(bin(B))) + bin(B)[2:]}")
    m = polyMult(A,B)
    reduced = polyMod(m,P)

    m = '0'*(10-len(bin(m))) + bin(m)[2:] # zeropad from left for each missing bit from 8 bits
    reduced = '0'*(10-len(bin(reduced))) + bin(reduced)[2:] # zeropad from left for each missing bit from 8 bits

    print(f"Resulting multiplication before reduction is {m}\nReduction result is {reduced}")

    if checkFromServer:
        print("Checking reduced result from server:")
        check_mult(reduced) 
    
    print()
    for i in range(2**8): # check all possible polynomials in GF(2^8)
        m = polyMult(A,i)
        reduced = polyMod(m,P) 
        if reduced == 1: # if result is 1, this polynomial is the modular multiplicative inverse
            inv = '0'*(10-len(bin(i)))+ bin(i)[2:]
            print(f"Multiplicative inverse of a in GF(2^8) is {inv}")
            break

    if checkFromServer:
        print("Checking multiplicative inverse from server:")
        check_inv(inv)

if __name__ == '__main__':
    Q4()
    