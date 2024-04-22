import cirq
import random

def prepare_qubits_using_bb84(len_key):
    # Alice and Bob choose their bases
    alice_bases = [random.choice(['+', 'x']) for _ in range(len_key)]
    bob_bases = [random.choice(['+', 'x']) for _ in range(len_key)]
    
    # Create qubits and the circuit
    alice_qubits = [cirq.LineQubit(i) for i in range(len_key)]
    circuit = cirq.Circuit()

    # Alice prepares qubits based on her bases
    for i, base in enumerate(alice_bases):
        if base == '+':
            circuit.append(cirq.H(alice_qubits[i]))  # Prepare in the diagonal basis (+)

    # Measurement based on Bob's bases
    for i, base in enumerate(bob_bases):
        if base == '+':
            circuit.append(cirq.H(alice_qubits[i]))  # Rotate to the diagonal basis before measurement
        circuit.append(cirq.measure(alice_qubits[i], key=f'm{i}'))

    return circuit, alice_bases, bob_bases, alice_qubits

def simulate_bb84(circuit, num_repetitions=1):
    simulator = cirq.Simulator()
    results = simulator.run(circuit, repetitions=num_repetitions)
    return results

def reconcile_key(alice_bases, bob_bases, measurement_results, len_key):
    key = ''
    for i in range(len_key):
        if alice_bases[i] == bob_bases[i]:
            # Correctly access the measurement result for the qubit
            measurement_key = f'm{i}'
            if measurement_key in measurement_results.measurements:
                bit = measurement_results.measurements[measurement_key][0, 0]
                key += str(bit)
    return key


def encrypt_message(key, binary_message):
    encrypted_message = ''
    key_len = len(key)
    for i, bit in enumerate(binary_message):
        encrypted_message += str(int(bit) ^ int(key[i % key_len]))
    return encrypted_message

def string_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)


def decrypt_message(key, encrypted_message):
    decrypted_binary = ''
    key_len = len(key)
    for i, bit in enumerate(encrypted_message):
        decrypted_binary += str(int(bit) ^ int(key[i % key_len]))  # XOR to decrypt
    return decrypted_binary

def binary_to_string(binary_message):
    # Split the binary message into chunks of 8 bits and convert each to a character
    chars = [chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)]
    return ''.join(chars)

# Main function to simulate the entire process
def send_and_receive_message():
    # The message to be sent
    message = "I love Quantum!"
    print("Original Message:", message)
    
    # Convert message to binary
    binary_message = string_to_binary(message)
    print("Binary Message:", binary_message)
    
    # Length of the binary message determines the number of qubits
    len_key = len(binary_message)
    
    # Prepare the quantum circuit for BB84 and perform the simulation
    circuit, alice_bases, bob_bases, alice_qubits = prepare_qubits_using_bb84(len_key)
    results = simulate_bb84(circuit)
    
    # Reconcile the key based on matching bases
    key = reconcile_key(alice_bases, bob_bases, results, len_key)
    print("Reconciled Key:", key)
    
    # Encrypt the message using the reconciled key
    encrypted_message = encrypt_message(key, binary_message)
    print("Encrypted Message:", encrypted_message)
    
    # Decrypt the message at Bob's end using the same key
    decrypted_binary = decrypt_message(key, encrypted_message)
    decrypted_message = binary_to_string(decrypted_binary)
    print("Decrypted Message:", decrypted_message)

# Call the function to simulate sending and receiving the message
send_and_receive_message()

