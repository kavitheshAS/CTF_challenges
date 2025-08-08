def m_to_bytes(m):

    message = b""
    for word in m:
        message += word.to_bytes(4, "big")  # Convert 32-bit word to 4 bytes (big-endian)
    return message

def remove_padding(message):

    padding_length = message[-1]  # Get the padding length from the last byte
    if padding_length > len(message):
        raise ValueError("Invalid padding length.")
    return message[:-padding_length]  # Remove the padding bytes

def main():
    # Given array m[] (32-bit integers)
    m = [
        0x505f4354, 0x467b4d72, 0x5f417c5f, 0x7c6d3435, 0x35306e5f, 0x74306c34,
        0x5f743469, 0x735f7730, 0x3431645f, 0x7730726b, 0x5f683368, 0x337d8000,
        0x00000000, 0x00000001, 0x00000000, 0x00000170
    ]
    m = [0x0a27d1d5, 0xe9573f2d, 0xf7390421, 0xf8e83e28, 0xa2fc7dcd, 0xab2ce1f6, 0x50f2b86c, 0x9a152582, 0x37045a44, 0xa7b45e2c, 0xb4e3f26b, 0xff7186ec, 0x66ff5b7c, 0x4d24e6a5, 0x7f18d66a, 0x0c343701]
    m = [0x505f4354,0x467b4d72,0x5f41756d,0x41353530,0x6e5f7430,0x6c345f74,0x3469735f,0x77303431,0x645f7730,0x726b5f68,0x6568337d,0x80000000,0x00000000,0x00000001,0x00000000,0x00000160]
    # Step 1: Convert m[] to bytes
    reconstructed_message = m_to_bytes(m)
    print("Reconstructed message (with padding):", reconstructed_message)

    # Step 2: Remove padding
    try:
        original_message = remove_padding(reconstructed_message)
        print("Original message (without padding):", original_message.decode())
    except ValueError as e:
        print("Error removing padding:", e)

if __name__ == "__main__":
    main()