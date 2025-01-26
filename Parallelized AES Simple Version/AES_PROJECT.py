from Crypto.Cipher import AES
from secrets import token_bytes
from multiprocessing import Pool
import os

#Substitution Box
S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

# Perform SubBytes
def sub_bytes(block):
    bytes_array = [int(block[i:i+2], 16) for i in range(0, len(block), 2)]
    substituted_bytes = [S_BOX[byte >> 4][byte & 0x0F] for byte in bytes_array]
    return ''.join(f"{byte:02x}" for byte in substituted_bytes)

# Perform ShiftRows 
def shift_rows(block):
    matrix = [block[i:i+8] for i in range(0, len(block), 8)]
    shifted_matrix = [
        matrix[0],
        matrix[1][2:] + matrix[1][:2],
        matrix[2][4:] + matrix[2][:4],
        matrix[3][6:] + matrix[3][:6],
    ]
    return ''.join(shifted_matrix)

# Perform MixColumns 
def mix_columns(block):
    def galois_multiply(a, b): # a (elements of the mix_matrix) and b are 2 bit numbers
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a # p is the result
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= 0x1b
            b >>= 1
        return p

    state = [[int(block[i+j:i+j+2], 16) for j in range(0, 8, 2)] for i in range(0, len(block), 8)]
    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ]
    mixed_state = [[0] * 4 for _ in range(4)]
    for row in range(4):
        for col in range(4):
            mixed_state[row][col] = (
                galois_multiply(mix_matrix[row][0], state[0][col]) ^
                galois_multiply(mix_matrix[row][1], state[1][col]) ^
                galois_multiply(mix_matrix[row][2], state[2][col]) ^
                galois_multiply(mix_matrix[row][3], state[3][col])
            )
    return ''.join(f"{byte:02x}" for row in mixed_state for byte in row)

# Perform AddRoundKey transformation on a single block
def add_round_key(block, key):
    block_bytes = [int(block[i:i+2], 16) for i in range(0, len(block), 2)]
    key_bytes = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
    result_bytes = [block_bytes[i] ^ key_bytes[i] for i in range(len(block_bytes))]
    return ''.join(f"{byte:02x}" for byte in result_bytes)

def print_block_as_matrix(block):
    matrix = [block[i:i+8] for i in range(0, len(block), 8)]  
    print("Matrix Form:")
    for row in matrix:
        print(" ".join([row[i:i+2] for i in range(0, len(row), 2)])) 

# Process a single block through all AES rounds
def process_block(block, round_key, num_rounds, block_id):
    results = []
    for round_num in range(1, num_rounds + 1):
        step_results = {"round": round_num, "block_id": block_id, "steps": {}}
        
        block = sub_bytes(block)
        step_results["steps"]["sub_bytes"] = block

        block = shift_rows(block)
        step_results["steps"]["shift_rows"] = block

        if round_num != num_rounds:
            block = mix_columns(block)
            step_results["steps"]["mix_columns"] = block

        block = add_round_key(block, round_key)
        step_results["steps"]["add_round_key"] = block
        
        results.append(step_results)
    return results

def main():
    input_choice = input("Do you want to enter plaintext or read from a file? (Enter 'plaintext' or 'file'): ").strip().lower()
    
    if input_choice == "plaintext":
        plaintext = input("Enter plaintext: ")
    elif input_choice == "file":
        file_path = input("Enter the file path: ").strip()
        if not os.path.exists(file_path):
            print("Error: File not found.")
            return
        with open(file_path, "r", encoding="utf-8") as f:
            plaintext = f.read()
    else:
        print("Invalid choice. Exiting.")
        return

    
    hex_representation = plaintext.encode("utf-8").hex()
    print(f"Hexadecimal: {hex_representation}")

    # block size for AES (128 bits = 16 bytes = 32 hex characters)
    block_size = 32

    def pad_to_block_size(hex_data, block_size=32):
        if len(hex_data) % block_size != 0:
            padding_length = block_size - len(hex_data) % block_size
            return hex_data + "0" * padding_length
        return hex_data

    padded_hex = pad_to_block_size(hex_representation)
    print(f"Padded Hexadecimal: {padded_hex}")

    blocks = [padded_hex[i:i+block_size] for i in range(0, len(padded_hex), block_size)]
    num_blocks = len(blocks)

    # Generate a random key using token_bytes
    key = token_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    round_key = key.hex()
    print(f"\nGenerated Round Key: {round_key}")

    # AES Encryption Parallelization
    num_rounds = 10  
    with Pool(processes=num_blocks) as pool:
        results = pool.starmap(process_block, [(block, round_key, num_rounds, idx) for idx, block in enumerate(blocks)])

    for round_num in range(1, num_rounds + 1):
        print(f"\n--- Round {round_num} ---")
        for step in ["sub_bytes", "shift_rows", "mix_columns", "add_round_key"]:
            if step == "mix_columns" and round_num == num_rounds:
                continue  
            print(f"\nStep: {step.replace('_', ' ').title()}")
            for block_result in results:
                for round_result in block_result:
                    if round_result["round"] == round_num:
                        print(f"Block {round_result['block_id'] + 1}:")
                        print_block_as_matrix(round_result['steps'][step])

    # Combine the final encrypted message
    final_encrypted_message = ''.join(
        block_result[-1]["steps"]["add_round_key"] for block_result in results
    )

    print("\nFinal Encrypted Message:")
    print(final_encrypted_message)

if __name__ == "__main__":
    main()
