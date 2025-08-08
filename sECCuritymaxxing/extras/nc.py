from pwn import remote 
import hashlib
from hashlib import sha1

j=200 #value of j shud be (1+val in range)? number of interactions

def inverse_mod(a, m):
    if m <= 0:
        raise ValueError("Modulus must be positive")

    a = a % m
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, m)
    
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} (mod {m})")
    
    return x % m

host='localhost' #Replace with the actual server's addres
port=5000 #Replace with the actual port number
conn=remote(host,port)

conn.recvuntil(b">")
conn.sendline(b"1")
conn.recvuntil(b">")
conn.sendline(b"0")
x = eval(conn.recvline().decode().strip())
r = int(x[0], 16)
s1 = int(x[1], 16)

print("loop")
for i in range(1,j):
    conn.recvuntil(b">")
    conn.sendline(b"1")
    conn.recvuntil(b">")
    conn.sendline(f"{i}".encode())
    conn.recvline()

conn.recvuntil(b">")
conn.sendline(b"1")
conn.recvuntil(b">")
conn.sendline(b"200")
x = eval(conn.recvline().decode().strip())
s2 = int(x[1], 16)

a, b  = 0, 7 
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)
p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

m1=str(0)
m2=str(200)

z1 = int(sha1(m1.encode()).hexdigest(), 16)
z2 = int(sha1(m2.encode()).hexdigest(), 16)

k_0=int((((z1-z2) % n)*inverse_mod(s1-s2,n))%n)
d=int(((((s1*k_0)%n)-z1)*inverse_mod(r,n))%n)
print(f"k_0:{k_0}")
print(f"d:{d}")


def add_points(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == y2:
        beta = (3 * x1 * x2 + a) * pow((2 * y1), -1, p)
    else:
        beta = (y2 - y1) * pow((x2 - x1), -1, p)
    x3 = (pow(beta, 2) - x1 - x2) % p
    y3 = (beta * (x1 - x3) - y1) % p
    return x3, y3

def is_on_curve(P, p):
    x, y = P
    assert (y * y) % p == (pow(x, 3, p) + a * x + b) % p

is_on_curve(G, p)

def apply_double_and_add_method(G, k, p):
    target_point = G
    k_binary = bin(k)[2:]
    for i in range(1, len(k_binary)):
        current_bit = k_binary[i]
        target_point = add_points(target_point, target_point, p)
        if current_bit == '1':
            target_point = add_points(target_point, G, p)
    is_on_curve(target_point, p)
    return target_point
Q = apply_double_and_add_method(G=G, k=d, p=p)

random_point=apply_double_and_add_method(G=G, k=k_0, p=p)

r_e=(random_point[0])%n 
rh=hex(r_e)
message="give_me_signature"

hash_int = int(hashlib.sha1(message.encode()).hexdigest(),16)
s_e= int(((hash_int + r * d) * pow(k_0,-1, n)) % n)
sh=hex(s_e)

print(r_e,s_e)

conn.recvuntil(b">")
conn.sendline(b"2")
conn.recvuntil(b"r:")
conn.sendline(f"{r_e}".encode())
conn.recvuntil(b"s:")
conn.sendline(f"{s_e}".encode())
print(conn.recvline().decode().strip())