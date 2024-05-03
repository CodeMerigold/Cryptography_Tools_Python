from Crypto.Cipher import AES
from Crypto.Cipher import DES

############ Begin DES AV input test ################

def des_input_av_test(inputblock, key, bitlist):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(inputblock)
    bit_counts = []
    for pos in bitlist:
        modified_inputblock = bytearray(inputblock)
        modified_inputblock[pos // 8] ^= 1 << (7 - pos % 8)
        modified_ciphertext = cipher.encrypt(bytes(modified_inputblock))
        bit_count = sum([bin(original_byte ^ modified_byte).count('1') for original_byte, modified_byte in zip(ciphertext, modified_ciphertext)])
        bit_counts.append(bit_count)
    return bit_counts

######### End DES AV input test ##############

############Begin DES Key test ##############

def des_key_av_test(inputblock, key, bit_list):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(inputblock)
    result = []
    for i in bit_list:
        modified_key = bytearray(key)
        modified_key[i // 8] ^= 1 << (7 - (i % 8))
        modified_cipher = DES.new(bytes(modified_key), DES.MODE_ECB).encrypt(inputblock)
        result.append(sum([bin(ciphertext[j] ^ modified_cipher[j]).count('1') for j in range(len(ciphertext))]))
    return result

############End DES Key test ##############

############# begin aes_input_av_test #############

def aes_input_av_test(inputblock, key, bitlist):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(inputblock)
    bit_counts = []
    for pos in bitlist:
        modified_inputblock = bytearray(inputblock)
        modified_inputblock[pos // 8] ^= 1 << (7 - pos % 8)
        modified_ciphertext = cipher.encrypt(bytes(modified_inputblock))
        # count the bit difference
        bit_count = sum([bin(original_byte ^ modified_byte).count('1') for original_byte, modified_byte in zip(ciphertext, modified_ciphertext)])
        bit_counts.append(bit_count)
    return bit_counts

########## end input av test ######################

######### Begin AES key AV test ##########

def aes_key_av_test(inputblock, key, bitlist):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(inputblock)
    result = []
    for i in bitlist:
        modified_key = bytearray(key)
        modified_key[i // 8] ^= 1 << (7 - (i % 8))
        modified_cipher = AES.new(bytes(modified_key), AES.MODE_ECB).encrypt(inputblock)
        result.append(sum([bin(ciphertext[j] ^ modified_cipher[j]).count('1') for j in range(len(ciphertext))]))
    return result

########## end AES key Test #############

# main func for testing aes_input_av_test

def main():
    aes_input_test = aes_input_av_test(b'thisoneis16bytes', b'veryverylongkey!', [5, 29, 38])
    print(aes_input_test)
    print(aes_key_av_test(b'thisoneis16bytes', b'veryverylongkey!', [5, 29, 38]))
    print()
    des_input_test = des_input_av_test(b'thisoneis16bytes', b'deskey!!', [3, 25, 36])
    print(des_input_test)
    print(des_key_av_test(b'thisoneis16bytes', b'deskey!!', [3, 25, 36]))

if __name__ == "__main__":
    main()
