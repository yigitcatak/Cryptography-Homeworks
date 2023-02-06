#%%
import re
from math import gcd

lookup ={chr(ord("A")+i):i for i in range(26)}
inv_lookup = {v:k for k,v in lookup.items()}

def Q1():
    ctext = "NGZZK"
    results = ["" for i in range(24)] # key 0 and 26 are skipped
    for i in range(24):
        for j in ctext:
            results[i] += inv_lookup[ (lookup[j]-i-1)%26 ]
        
    for idx, dtext in enumerate(results):
        print(f"for key {idx+1} resulting dechipered text is: {dtext}")

def Q2():
    ctext = "ZJOWMJ ZJGC BS UEVRSCC, KSZ ZJSFS GC USZJOV GR GZ."
    frequency = {}
    for i in ctext:
        if i == " " or i == "." or i == ",":
            continue

        if i not in frequency:
            frequency[i] = 1
        else:
            frequency[i] += 1

    maxv = 0
    for k,v in frequency.items():
        if v > maxv:
            maxv = v
            maxc1 = k
        elif v == maxv:
            maxc2 = k
    print(f"Characters that occur the most are \"{maxc1}\" and \"{maxc2}\". They appear {maxv} times.\n")

    alphas = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

    for alpha in alphas:
        alpha_inv = pow(alpha, -1, 26)
        
        beta1 = (lookup[maxc1] - lookup["T"]*alpha)%26
        beta2 = (lookup[maxc2] - lookup["T"]*alpha)%26

        dtext1,dtext2 = "",""
        for i in ctext:
            if i == " " or i == "." or i == ",":
                dtext1 += i
                dtext2 += i
            else:
                dtext1 += inv_lookup[((lookup[i]-beta1)*alpha_inv)%26]
                dtext2 += inv_lookup[((lookup[i]-beta2)*alpha_inv)%26]

        print(f"For character {maxc1} to be \"T\" with alpha value {alpha}, beta value must be {beta1}")
        print(f"The deciphered text is:\n{dtext1}\n")

        print(f"For character {maxc2} to be \"T\" with alpha value {alpha}, beta value must be {beta2}")
        print(f"The deciphered text is:\n{dtext2}\n")

def Q5():
    d = {'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8, 'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24, 'Z':25, '.':26, ' ':27}
    d2 = {k+k2:28*v + v2 for k,v in d.items() for k2,v2 in d.items()}
    d2_inv = {v:k for k,v in d2.items()}
    alphas = [i for i in range(len(d2)) if gcd(i,len(d2))==1]

    ctext_ending = ".X"
    ptext_ending = "YT"

    alpha_beta_pairs = []
    for alpha in alphas:
        for beta in range(len(d2)):
            if (alpha*d2[ctext_ending] + beta)%len(d2) == d2[ptext_ending]:
                alpha_beta_pairs.append((alpha,beta))
    
    print(f"There are {len(alphas)} numbers that are coprime with {len(d2)}, which are all the possible alpha values.\n")

    ctext = "ZDZUKEO.AANDOGIJTLNEKEPHZUQDX NDS VLNDJGQLYDVSBU.DER.K.UYT"

    for alpha,beta in alpha_beta_pairs:
        alpha_inv = pow(alpha, -1, len(d2))
        dtext = ""
        for j in range(0,len(ctext),2):
            dtext += d2_inv[ ((d2[ctext[j:j+2]]-beta)*alpha_inv)%len(d2) ]

        print(f"For alpha: {alpha} and beta: {beta}")
        print(f"The deciphered text is:\n{dtext}\n")

def Bonus():
    ctext = "JR WYDUGQ AR LRG BTFWB'U UECDC YVTF S CYVNE LY JVS QZYWYDCJC, CAD FAC NRGQ KZTRAB MXYVTRAXIYY, YK SH GHC DOXRL DDYQES UWBG GIJLSPT UN SXF FILCSPT DMOX VB TFW RGNVC SXF YULYO QS TFW CGN. TFW GKQE PGYOF SCWWGQ TMG XCERMO PQE HGK BQYLGFQ INIR, SXF GO FAWURLD ZO YNS GF DGERMJ VGFT FAC DEOYV CJBUJVOTF SFGENQ CMDVKQE UADJ GHC VYQEWYQC QE SUWOR GHC TBKP-A-ZJKE SRME DJR LMO WCATCD. RG EEAGSNRD DJYO FIBW DQ FIBW LGGWCWX VUE TSBKBUQ GLLRCRK KPQ MSDDKCLGWN VUE FSJCEDQ LRCG IL JOCYIRQ VQQGCV YPYY GF RKF MGFN. DRTUWOP N GPSXF CIYFY CAD Y UOPGRC-LKDYE NAVGQ HGYR YVTF TYQXS USC UCAAW PQE A FSVH N DMROP GO USVM NBPWKUG, YCL RG RSQSIGQ IR OSVU TPWZKQARAYP. UIQ ZOCIY YJWU UULY VQBSCDI CG HGK CKQEQ. ZO FVD LGD MAOU ORCG TM VY YVTF LRQFE YJWU NNB ZKPQS, YFN YUEL, LY JVS CPMKGEB NSUVOL, GXG NRK KOGZEB DSCOLC LY DEUQZ KINILKD VUE ZGYMF OL LRG GAZDO, JR LSJMJRD YOKA YIIW K HEIEZDGAEB ZYTFE, ZSBGYY KACUVNE LRG CIYFY UGOMD. RG JARURGQ TFW OCFY USVM BF RZO QGHCJ SP SRMFD QS HGE, KPQ FMJ DJR FGJCV GIKW BGNLGROF GHYL RKF WYDU YNS BAPHRRCFD HEOK LRCG OD GDJRR KWX. JR EVHOTVELUOF N MMEOPGAPQ ZCAG MX CJNMC LRCG HC KRQHLB OKNX SM MXEBURZVA. GHC KGGNT ZMBUG TFJYWTH RZO UXIL GP JVS DGBGUEYV SP GILQ LGNDQ, SXF UE NSEURD YFN OBPNWN JVS ZJYPMEB XKER WGLR JVS FSXFXEPURKRF."
    ctext_stripped = ""
    ctext_trigrams = []
    single_letter_word_indices = []
    total_index = 0

    for i in ctext.split():
        i = re.sub("[^A-Z]+", "", i)
        l = len(i)

        ctext_stripped += i
        if l == 1:
            single_letter_word_indices.append(total_index)
        elif l == 3:
            ctext_trigrams.append(i)
        total_index += l

    word_frequency = {}
    for i in ctext_trigrams:
        if i not in word_frequency:
            word_frequency[i] = 1
        else:
            word_frequency[i] += 1

    maxv = 0
    for k,v in word_frequency.items():
        if v > maxv:
            maxv = v
            max_trigram = k

    print(f"Trigram that occur the most is \"{max_trigram}\" it appears {maxv} times.\n")
    
    indices = [0 for i in range(maxv)]
    indices[0] = ctext_stripped.find(max_trigram)
    for i in range(1,maxv):
        indices[i] = indices[i-1] + ctext_stripped[indices[i-1]+3:].find(max_trigram) + 3 

    differences = [0 for i in range(maxv-1)]
    for i in range(maxv-1):
        differences[i] = indices[i+1] - indices[i]
    
    key_length = gcd(*differences)
    print(f"Trigram \"{max_trigram}\" appears at indices {indices}. The index differences between occurances are {differences}.\n")
    print(f"gcd of these differences is {key_length}. Therefore {key_length} is the most probable key length for this encryption.\n")

    groups = [ctext_stripped[i::key_length] for i in range(key_length)]

    single_letter_word_groups = []
    for idx, i in enumerate(single_letter_word_indices):
        single_letter_word_groups.append(i%key_length)
        single_letter_word_indices[idx] = i//key_length
    single_letter_words = [groups[group][idx] for group,idx in zip(single_letter_word_groups,single_letter_word_indices)]


    print(f"Probable shift ammount for each group is calculated based on the single letters in the text being \"A\"  is as follows:")
    shifts = [None for i in range(key_length)]
    for group,letter in zip(single_letter_word_groups,single_letter_words):
        shifts[group] = (lookup["A"] - lookup[letter])%26
    print(f"{shifts}\n")

    print(f"Probable shift ammount for each group is calculated based on the distance between the most frequent letter in the group and the letter \"E\" is as follows:")
    shifts2 = [0 for i in range(key_length)]
    for i in range(key_length):
        freq = {}
        maxf = 0
        maxc = ""
        for j in groups[i]:
            if j not in freq:
                freq[j] = 1
            else:
                freq[j] += 1

            if freq[j] > maxf:
                maxf = freq[j]
                maxc = j

        shifts2[i] = (lookup["E"] - lookup[maxc])%26
        print(f"For group {i+1} the letter {maxc} appears the most with frequency {maxf*100/len(groups[i])}%. The shift is {shifts2[i]}")
    print()

    
    shifts3 = [[2,24], [13,2], [0,16], [24,20], [18,3], [10,21]]
    print(f"Furthermore, the most probable 2 shift ammounts for each group based on entropy loss compared with english language letter frequency is as follows:")
    print(f"{shifts3}\n") 

    print("Therefore \"24\" seems the most reasonable shift for the first group as it appears in both entropy analysis and the distance to the letter \"E\". I use the rest of the shifts as found in the distance to letter \"A\" for single letters.\n")
    shifts[0] = shifts2[0]
    the_key = "".join([inv_lookup[i] for i in shifts])
    print(f"Shift ammounts are {shifts}, Key is {the_key}\n")
    
    shifted_groups = ["" for i in range(key_length)]
    for idx,(shift,group) in enumerate(zip(shifts,groups)):
        for ch in group:
            shifted_groups[idx] += inv_lookup[(lookup[ch] + shift)%26]

    group_lengths = [len(groups[i]) for i in range(key_length)]

    dtext_stripped = ""
    for i in range(max(group_lengths)):
        for j in range(key_length):
            if i < len(shifted_groups[j]):
                dtext_stripped += shifted_groups[j][i]

    dtext = ""
    print_index = 0
    for i in ctext:
        if i in lookup:
            dtext += dtext_stripped[print_index]
            print_index += 1
        else:
            dtext += i
    print(dtext) 

if __name__ == '__main__':
    gcd()