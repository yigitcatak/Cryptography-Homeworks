# Do not forget to install pycryptodome if not already installed
# pip install pycryptodome
#%%
import random
from Crypto.Hash import SHA3_256
from Crypto import Random
import json

def Reduction(x, Alphabet, length, i):
  pwd = ""
  t = x+i
  size = len(Alphabet)
  for j in range(0,length):
    pwd += Alphabet[t%size]
    t = t >> 5
  return pwd

Alphabet = {0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H', 8:'I', 9:'J', 10:'K', 11:'L', 12:'M', 13:'N', 14:'O', 15:'P', 16:'Q', 17:'R', 18:'S', 19:'T', 20:'U', 21:'V', 22:'W', 23:'X', 24:'Y', 25:'Z'}
alpha_len = len(Alphabet)
pwd_len = 6
pwd_space = alpha_len**pwd_len 
t = 2**16+1
m = 2*(pwd_space//t)


# Example for computing one link in the chain; i.e., pwd(i+1) = R(H(pwd(i)))
# print("This is how you compute one link in the hash chain")
i=0 #ith password
pwd_i = "UTKUAY"
hash = SHA3_256.new(pwd_i.encode('utf-8')) # hash it
digest = int.from_bytes(hash.digest(), byteorder='big') # convert the hash into an integer
pwd_i1 = Reduction(digest%pwd_space, Alphabet, pwd_len, i) # Reduce it

# Read the rainbow table
with open("rainbowtable.txt","r") as f:
    Rainbow_Table = [i.strip("\n").split(" ") for i in f]


# Digests
given_digests = [0] * 10
given_digests[0] = 68129488042014195110038312742631656560169409657135532041458285223411948948866 
given_digests[1] = 46239392724540305843773223468371007649789714008888724404577522963606526935663
given_digests[2] = 110406129499448663314892102624048071751195087034833389280698385840405018797245
given_digests[3] = 65313482800699121689791056564159588572328243104099706346813528273728803821799
given_digests[4] = 26488608998776111812821955234078050783380240707584374240367068144139270378566
given_digests[5] = 87733593915723119912876120695727808623311037020587654316551147774042989670919
given_digests[6] = 16344842234414968973159367286253689000345294679806407070533658658954772132386
given_digests[7] = 11069735230566290933060635309207163848287223244609233713537878009248132037840
given_digests[8] = 20733450778515206264852019437941451511769124738113724518661416850129619314254
given_digests[9] = 106933681333642373745676425544794836262079892073184965405213516175561492091091

# Solution


if __name__ == '__main__':
    table_length = len(Rainbow_Table)
    R0 = ['']*table_length
    R1 = ['']*table_length
    passwords = ['']*len(given_digests)

    for idx, (first, second) in enumerate(Rainbow_Table):
        R0[idx] = first
        R1[idx] = second


    for idx, d in enumerate(given_digests):
        found = False
        temp_int = d
        
        initial_reduction = Reduction(d%pwd_space, Alphabet, pwd_len, i)

        for i in range(t):
            temp_digest = Reduction(temp_int%pwd_space, Alphabet, pwd_len, i)
            if temp_digest in R1:
                table_idx = R1.index(temp_digest)
                found_pwd = R0[table_idx]
                temp_digest = found_pwd
                print(f"Found the password {found_pwd} to be the password of given digest {idx+1}. Now will reverse check.")
                break

            temp_hash = SHA3_256.new(temp_digest.encode('utf-8'))
            temp_int = int.from_bytes(temp_hash.digest(), byteorder='big')

        for i in range(t):
            if initial_reduction == temp_digest:
                print(f"Reverse check is success, the password is for given digest.")
                found = True
                break
            temp_hash = SHA3_256.new(temp_digest.encode('utf-8'))
            temp_int = int.from_bytes(temp_hash.digest(), byteorder='big') # convert the hash into an integer
            temp_digest = Reduction(temp_int%pwd_space, Alphabet, pwd_len, i) # Reduce it
            
        if found:
            passwords[idx] = found_pwd
    print(passwords)
    