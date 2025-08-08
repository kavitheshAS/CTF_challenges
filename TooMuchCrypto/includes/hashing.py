from blake_h import state256, u8to32_big, G, constant, u32to8_big, padding
import numpy as np
from Crypto.Util.number import getStrongPrime
from random import shuffle
mm=[]
v0510=[]

def initialize(S: state256):
    S.h=np.array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ],dtype=np.uint32)
    S.t = np.array([0,0], dtype=np.uint32)
    S.buflen = 0
    S.nullt = 0
    S.s = np.array([0,0,0,0], dtype=np.uint32)


def round_function(S: state256, block: bytes):
    v = [np.uint32(0)] * 16
    m = [np.uint32(0)] * 16

    # Convert 8-bit blocks into 32-bit big-endian format
    for i in range(16):
        m[i] = np.uint32(u8to32_big(block[i * 4:(i + 1) * 4]))

    # Initial states
    for i in range(8):
        v[i] = np.uint32(S.h[i])

    # Set up the rest of the states using constants
    v[8] = np.uint32(S.s[0] ^ constant[0])
    v[9] = np.uint32(S.s[1] ^ constant[1])
    v[10] = np.uint32(S.s[2] ^ constant[2])
    v[11] = np.uint32(S.s[3] ^ constant[3])
    v[12] = np.uint32(constant[4])
    v[13] = np.uint32(constant[5])
    v[14] = np.uint32(constant[6])
    v[15] = np.uint32(constant[7])

    # XOR with t if block doesn't have padding-bits
    if not S.nullt:
        v[12] ^= np.uint32(S.t[0])
        v[13] ^= np.uint32(S.t[0])
        v[14] ^= np.uint32(S.t[1])
        v[15] ^= np.uint32(S.t[1])

    # Save initial states before each half round
    v0 = v[:]

    # Run half-core function for 3 times
    # 0.5 round
    G(v, m, 0, 0, 4, 8, 12, 0)
    G(v, m, 0, 1, 5, 9, 13, 2)
    G(v, m, 0, 2, 6, 10, 14, 4)
    G(v, m, 0, 3, 7, 11, 15, 6)
    v0_5 = v[:]

    # # 1 round
    G(v, m, 0, 0, 5, 10, 15, 8)
    G(v, m, 0, 1, 6, 11, 12, 10)
    G(v, m, 0, 2, 7, 8, 13, 12)
    G(v, m, 0, 3, 4, 9, 14, 14)
    v1 = v[:]

    # 1.5 round
    G(v, m, 1, 0, 4, 8, 12, 0)
    G(v, m, 1, 1, 5, 9, 13, 2)
    G(v, m, 1, 2, 6, 10, 14, 4)
    G(v, m, 1, 3, 7, 11, 15, 6)
    v1_5 = v[:]

    # Update the hash with all updated states
    for i in range(16):
        S.h[i % 8] ^= np.uint32(v[i])

    for i in range(8):
        S.h[i] ^= np.uint32(S.s[i % 4])

  
    print("\n")
    for i in range(16):
        print(f"v0[{i}] = {v0[i]:08x}\tv0_5[{i}] = {v0_5[i]:08x}\tv1[{i}] = {v1[i]:08x}\tv1_5[{i}] = {v1_5[i]:08x}\tm[{i}] = {m[i]:08x}")
    print("\n")

    print("\n")
    for i in range(16):
        v0int=int(v0[i])
        v15int=int(v1_5[i])
        v15by=v15int.to_bytes((v15int.bit_length()+7)//8,"big")
        v0by=v0int.to_bytes((v0int.bit_length()+7)//8,"big")
        print(f"v0[{i}] = {rsa(v0by):08x}\nv1_5[{i}] = {rsa(v15by):08x}")
        if(i==8 or i==10 or i==11):
            mm.append(m[i])
        if(i==10):
            v0510.append(v0_5[i])

    print("\n")


def pad_and_round(S: state256, data: bytes, inlen: int):
    left = S.buflen
    fill = 64 - left

    # If there is leftover data and enough to fill a block
    if left and inlen >= fill:
        S.buf[left:left + fill] = np.frombuffer(data[:fill], dtype=np.uint8)
        S.t[0] += 512
        if S.t[0] == 0:
            S.t[1] += 1
        round_function(S, S.buf)
        data = data[fill:]
        inlen -= fill
        left = 0

    # Process full blocks
    while inlen >= 64:
        S.t[0] += 512
        if S.t[0] == 0:
            S.t[1] += 1
        round_function(S, data[:64])
        data = data[64:]
        inlen -= 64

    # Handle remaining data
    if inlen > 0:
        S.buf[left:left + inlen] = np.frombuffer(data[:inlen], dtype=np.uint8)
        S.buflen = left + inlen
    else:
        S.buflen = 0

    
def final_block(S):
    msglen = np.zeros(8, dtype=np.uint8)  # 8 bytes for message length
    zo = np.uint8(0x01)
    oo = np.uint8(0x81)
    
    lo = np.uint32(S.t[0] + (S.buflen << 3))
    hi = np.uint32(S.t[1])

    # Space fill is less than 2^32 bits
    if lo < (S.buflen << 3):
        hi += 1

    # Get the length of the message in 64-bit form (Big Endian)
    msglen[:4] = u32to8_big(hi)  # Start at index 0 for hi
    msglen[4:] = u32to8_big(lo)  # Start at index 4 for lo

    # Padding logic
    if S.buflen == 55:
        S.t[0] -= 8
        pad_and_round(S, np.array([oo], dtype=np.uint8), 1)
    else:
        if S.buflen < 55:
            if S.buflen == 0:
                S.nullt = 1

            S.t[0] -= 440 - (S.buflen << 3)
            pad_and_round(S, padding, 55 - S.buflen)
        else:
            S.t[0] -= 512 - (S.buflen << 3)
            pad_and_round(S, padding, 64 - S.buflen)
            S.t[0] -= 440
            pad_and_round(S, padding[1:], 55)
            S.nullt = 1

        # Add one after padding 0 bits
        pad_and_round(S, np.array([zo], dtype=np.uint8), 1)
        S.t[0] -= 8

    S.t[0] -= 64
    pad_and_round(S, msglen, 8)

    # Convert 32-bit blocks into 8-bit hash output in big-endian
    out = bytearray(32)
    out[0:4] = u32to8_big(S.h[0])
    out[4:8] = u32to8_big(S.h[1])
    out[8:12] = u32to8_big(S.h[2])
    out[12:16] = u32to8_big(S.h[3])
    out[16:20] = u32to8_big(S.h[4])
    out[20:24] = u32to8_big(S.h[5])
    out[24:28] = u32to8_big(S.h[6])
    out[28:32] = u32to8_big(S.h[7])

    return out

def blake32(data: bytes) -> bytearray:
    S = state256()
    initialize(S)
    pad_and_round(S, data, len(data))
    out = final_block(S)
    return bytes(out).hex()

def rsa(flag):
    p=getStrongPrime(1024)
    q=getStrongPrime(1024)
    N=p*q
    e=0x10001
    m=int.from_bytes(flag,"big")
    c=pow(m,e,N)
    p_bytes=p.to_bytes(128,"big")
    q_bytes=q.to_bytes(128,"big")
    fraction_size=2
    p_chunks = [int.from_bytes(p_bytes[i : i + fraction_size], "big") for i in range(0, len(p_bytes), fraction_size)]
    q_chunks = [int.from_bytes(q_bytes[i : i + fraction_size], "big") for i in range(0, len(q_bytes), fraction_size)]
    shuffle(p_chunks)
    shuffle(q_chunks)
    with open("output.py", "a") as f:
        f.write(f"N={str(N)}\n")
        f.write(f"c={str(c)}\n")
        f.write(f"p_chunks={str(p_chunks)}\n")
        f.write(f"q_chunks={str(q_chunks)}\n")
    return c

if __name__ == "__main__":
        message = b"P_CTF{Mr_AumA550n_t0l4_t4is_w041d_w0rk_heh3}"
        
        hash_output = str(blake32(message))
        
        print(f"Message: {message}")
        print(f"Hash: {hash_output}")
        with open("output.py", "a") as f:
            f.write(str(mm))
            f.write(str(v0510))
