from flask import Flask, request, render_template, send_from_directory
import time
import tracemalloc
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

import matplotlib
matplotlib.use('Agg')

app = Flask(__name__)

# AES Functions
def generate_aes_key(key_size):
    return os.urandom(key_size // 8)

def generate_iv():
    return os.urandom(16)

def aes_encrypt(key, iv, plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def benchmark_aes(input_data, key_size, iterations):
    key = generate_aes_key(key_size)
    iv = generate_iv()

    encryption_times = []
    decryption_times = []
    encryption_memories = []
    decryption_memories = []

    for _ in range(iterations):
        tracemalloc.start()
        start_time = time.time()
        ciphertext = aes_encrypt(key, iv, input_data)
        encryption_time = time.time() - start_time
        encryption_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        tracemalloc.start()
        start_time = time.time()
        decrypted_text = aes_decrypt(key, iv, ciphertext)
        decryption_time = time.time() - start_time
        decryption_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert input_data == decrypted_text, "Decryption failed!"

        encryption_times.append(encryption_time)
        decryption_times.append(decryption_time)
        encryption_memories.append(encryption_memory[1])
        decryption_memories.append(decryption_memory[1])

    return {
        "key_size": key_size,
        "iterations": iterations,
        "avg_enc_time": sum(encryption_times) / iterations,
        "avg_dec_time": sum(decryption_times) / iterations,
        "enc_throughput": iterations / sum(encryption_times),
        "dec_throughput": iterations / sum(decryption_times),
        "avg_enc_memory": sum(encryption_memories) / iterations,
        "avg_dec_memory": sum(decryption_memories) / iterations,
        "input_size": len(input_data),
    }

def plot_results(results):
    key_sizes = [res['key_size'] for res in results]
    enc_times = [res['avg_enc_time'] for res in results]
    dec_times = [res['avg_dec_time'] for res in results]
    enc_memories = [res['avg_enc_memory'] for res in results]
    dec_memories = [res['avg_dec_memory'] for res in results]
    enc_throughput = [res['enc_throughput'] for res in results]
    dec_throughput = [res['dec_throughput'] for res in results]

    plt.figure(figsize=(10, 15))

    plt.subplot(3, 1, 1)
    plt.plot(key_sizes, enc_times, marker='o', label='Encryption Time')
    plt.plot(key_sizes, dec_times, marker='o', label='Decryption Time')
    plt.title('AES Encryption and Decryption Times')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (s)')
    plt.legend()
    plt.grid(True)

    plt.subplot(3, 1, 2)
    plt.plot(key_sizes, enc_memories, marker='o', label='Encryption Memory')
    plt.plot(key_sizes, dec_memories, marker='o', label='Decryption Memory')
    plt.title('AES Memory Usage')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Memory (bytes)')
    plt.legend()
    plt.grid(True)

    plt.subplot(3, 1, 3)
    plt.plot(key_sizes, enc_throughput, marker='o', label='Encryption Throughput')
    plt.plot(key_sizes, dec_throughput, marker='o', label='Decryption Throughput')
    plt.title('AES Throughput')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Throughput (ops/sec)')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig("static/aes_benchmark.png")  # Save the graph in the static folder

from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            input_data = request.form['input_data'].encode()  # Encode input to bytes
            iterations = int(request.form.get('iterations', 1))  # Default to 1 iteration if not provided

            # Perform AES benchmarking for 128-bit, 192-bit, and 256-bit keys
            results = [
                benchmark_aes(input_data, 128, iterations),
                benchmark_aes(input_data, 192, iterations),
                benchmark_aes(input_data, 256, iterations),
            ]

            # Plot results
            plot_results(results)

            # Render the same index.html template with results
            return render_template('index.html', results=results, graph_filename="aes_benchmark.png")
        except Exception as e:
            return f"Error: {str(e)}", 400

    # Render the input form without results (initial state)
    return render_template('index.html', results=None)
  # Render the first page form


if __name__ == '__main__':
    app.run(debug=True)
