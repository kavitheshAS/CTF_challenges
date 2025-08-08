import ast
from collections import deque
from Crypto.Util.number import inverse, long_to_bytes

def bfs_find_p_q(p_chunks, q_chunks, N, length):
    queue = deque([(0, [], [])])

    while queue:
        i, current_ps, current_qs = queue.popleft()

        if i == length:
            return current_ps, current_qs

        partial_N = N % 2 ** (16 * (i + 1))
        partial_p_poly = sum(
            [pi * (2 ** (16 * idx)) for idx, pi in enumerate(current_ps)]
        ) % (2 ** (16 * (i + 1)))
        partial_q_poly = sum(
            [qi * (2 ** (16 * idx)) for idx, qi in enumerate(current_qs)]
        ) % (2 ** (16 * (i + 1)))

        for pi in p_chunks:
            for qi in q_chunks:
                if (
                    (partial_p_poly + pi * (2 ** (16 * i)))
                    * (partial_q_poly + qi * (2 ** (16 * i)))
                ) % (2 ** (16 * (i + 1))) == partial_N:
                    queue.append((i + 1, current_ps + [pi], current_qs + [qi]))

    raise Exception("No valid solution found.")

def decrypt_rsa(N, c, p_chunks, q_chunks):
    LENGTH = len(p_chunks)

    # Find p and q using BFS
    found_ps, found_qs = bfs_find_p_q(p_chunks, q_chunks, N, LENGTH)

    # Reconstruct p and q
    p = sum([pi * (2 ** (16 * idx)) for idx, pi in enumerate(found_ps)])
    q = sum([qi * (2 ** (16 * idx)) for idx, qi in enumerate(found_qs)])

    # Ensure p * q matches N
    assert p * q == N

    # Decrypt the message
    e = 0x10001
    m = pow(c, inverse(e, (p - 1) * (q - 1)), p * q)
    plaintext = long_to_bytes(m)
    return plaintext.hex()

# Read the file and process
file_name = "output.py"
decrypted_results = []

with open(file_name, "r") as file:
    lines = file.readlines()

# Process 4 lines at a time
for i in range(0, len(lines), 4):
    try:
        # Parse the variables from each chunk
        N = int(lines[i].split('=')[1].strip())
        c = int(lines[i + 1].split('=')[1].strip())
        p_chunks = ast.literal_eval(lines[i + 2].split('=')[1].strip())
        q_chunks = ast.literal_eval(lines[i + 3].split('=')[1].strip())

        # Decrypt using the parsed values
        decr_m = decrypt_rsa(N, c, p_chunks, q_chunks)
        
        decr_m = f"0x{decr_m}"
        print(decr_m)
        # decr_m=int((decr_m))
        decrypted_results.append(decr_m)

    except Exception as e:
        print(f"Error processing chunk starting at line {i + 1}: {e}")

v0=[]
v1_5=[]
for i in range(len(decrypted_results)):
    if(i%2==0):
        v0.append(decrypted_results[i])
    else:
        v1_5.append(decrypted_results[i])

print(f"v0={v0}")
print(f"v1_5={v1_5}")

v0=['0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f', '0x9b05688c', '0x1f83d9ab', '0x5be0cd19', '0x243f6a88', '0x85a308d3', '0x13198a2e', '0x03707344', '0xa4093942', '0x299f30b0', '0x082efa98', '0xec4e6c89']
v1_5=['0xbf62a2ea', '0xaa70e06d', '0x3e9d3cc3', '0x43b21c89', '0xec70ced6', '0xe9dc156e', '0xb99bae6a', '0xf6899c17', '0x2fec24f1', '0x5e513866', '0x63f3aa5e', '0xee91c249', '0x2f201c62', '0x2441fc91', '0x6c40e18e', '0x888657f2']