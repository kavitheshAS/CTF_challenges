from Crypto.Util.number import getStrongPrime
from random import shuffle
# output_file="output.txt"

flag = b"1779033703"


p = getStrongPrime(1024)
# print(p)
q = getStrongPrime(1024)

N = p * q
e = 0x10001
# print(e)
m = int.from_bytes(flag, "big")
c = pow(m, e, N)


# "Aaaaargh!" -- A sharp, piercing scream shattered the silence.

p_bytes = p.to_bytes(128, "big")
# print(p_bytes)
q_bytes = q.to_bytes(128, "big")

fraction_size = 2 #splits into 2 byte segments ,cud be increased
#the below lines split the p_bytesinto chunks of size fraction_size and converts ech chunk back into an integer 
p_splitted = [int.from_bytes(p_bytes[i : i + fraction_size], "big") for i in range(0, len(p_bytes), fraction_size)]
q_splitted = [int.from_bytes(q_bytes[i : i + fraction_size], "big") for i in range(0, len(q_bytes), fraction_size)]

shuffle(p_splitted)
shuffle(q_splitted)

print(f"N = {N}")
print(f"c = {c}")
print(f"p_splitted = {p_splitted}")
print(f"q_splitted = {q_splitted}")

# with open("output.py", "w") as f:

#     f.write(f"N: {str(N)}\n")
#     f.write(f"c: {str(c)}\n")
#     f.write(f"p_splitted: {str(p_splitted)}\n")
#     f.write(f"q_spllited: {str(q_splitted)}\n")
   
