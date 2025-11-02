import socket
import time

HOST = "styx.ics.uci.edu"
PORT = 9000
INTERVAL = 10

def is_online(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

if __name__ == "__main__":
    print(f"Start monitoring {HOST}:{PORT}")
    while True:
        if is_online(HOST, PORT):
            print("ONLINE!!!! ONLINE!!!! ONLINE!!!! ONLINE!!!! ONLINE!!!! ONLINE!!!! ONLINE!!!! ")
        else:
            print("Offline")
        time.sleep(INTERVAL)