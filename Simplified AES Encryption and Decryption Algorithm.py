import sys

# Substitution Box
subBox = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
          0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

# Inverse Substitution Box
subBoxInv = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
             0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]

# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
roundKeys = [None] * 6


def multiply(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    result = 0
    while p2:
        if p2 & 0b1:
            result ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return result & 0b1111


def intToVector(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf, n & 0xf]


def vectorToInt(m):
    """Convert a 4-element vector into a 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]


def addKey(s1, s2):
    """Add two keys in GF(2^4)"""
    return [i ^ j for i, j in zip(s1, s2)]


def substituteNibbles(subBox, s):
    """Nibble substitution function"""
    return [subBox[e] for e in s]


def shiftRows(s):
    """Shift rows within the state"""
    return [s[0], s[1], s[3], s[2]]


def expandKey(key):
    """Generate the three round keys"""
    def substituteAndSwapNibbles(b):
        """Swap each nibble and substitute it using the Substitution Box"""
        return subBox[b >> 4] + (subBox[b & 0x0f] << 4)

    rCon1, rCon2 = 0b10000000, 0b00110000
    roundKeys[0] = (key & 0xff00) >> 8
    roundKeys[1] = key & 0x00ff
    roundKeys[2] = roundKeys[0] ^ rCon1 ^ substituteAndSwapNibbles(roundKeys[1])
    roundKeys[3] = roundKeys[2] ^ roundKeys[1]
    roundKeys[4] = roundKeys[2] ^ rCon2 ^ substituteAndSwapNibbles(roundKeys[3])
    roundKeys[5] = roundKeys[4] ^ roundKeys[3]


def encrypt(plaintext):
    """Encrypt the plaintext block"""
    def mixColumns(s):
        return [s[0] ^ multiply(4, s[2]), s[1] ^ multiply(4, s[3]),
                s[2] ^ multiply(4, s[0]), s[3] ^ multiply(4, s[1])]

    state = intToVector(((roundKeys[0] << 8) + roundKeys[1]) ^ plaintext)
    state = mixColumns(shiftRows(substituteNibbles(subBox, state)))
    state = addKey(intToVector((roundKeys[2] << 8) + roundKeys[3]), state)
    state = shiftRows(substituteNibbles(subBox, state))
    return vectorToInt(addKey(intToVector((roundKeys[4] << 8) + roundKeys[5]), state))


def decrypt(ciphertext):
    """Decrypt the ciphertext block"""
    def inverseMixColumns(s):
        return [multiply(9, s[0]) ^ multiply(2, s[2]), multiply(9, s[1]) ^ multiply(2, s[3]),
                multiply(9, s[2]) ^ multiply(2, s[0]), multiply(9, s[3]) ^ multiply(2, s[1])]

    state = intToVector(((roundKeys[4] << 8) + roundKeys[5]) ^ ciphertext)
    state = substituteNibbles(subBoxInv, shiftRows(state))
    state = inverseMixColumns(addKey(intToVector((roundKeys[2] << 8) + roundKeys[3]), state))
    state = substituteNibbles(subBoxInv, shiftRows(state))
    return vectorToInt(addKey(intToVector((roundKeys[0] << 8) + roundKeys[1]), state))


if __name__ == '__main__':

    plaintext = 0b0110111101101011
    key = 0b1010011100111011
    expected_ciphertext = 0b0000011100111000

    expandKey(key)
    ciphertext = encrypt(plaintext)

    if ciphertext == expected_ciphertext:
        print("Ciphertext:", bin(ciphertext)[2:].zfill(16))
        decrypted_plaintext = decrypt(ciphertext)
        if decrypted_plaintext == plaintext:
            print("Decrypted plaintext:", bin(decrypted_plaintext)[2:].zfill(16))
            print("Encryption and decryption successful.")
        else:
            print("Decryption error")
    else:
        print("Encryption error")
        print("Expected ciphertext:", bin(expected_ciphertext)[2:].zfill(16))

    sys.exit()