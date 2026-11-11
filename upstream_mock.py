import socket

HOST = "127.0.0.1"
PORT = 5354
MISSING = "missing.example.net"
OK_IP, OK_TTL = "198.51.100.7", 5

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Upstream mock listening on {HOST}:{PORT} (Ctrl+C to stop)", flush=True)
    counter = 0
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            parts = data.decode("utf-8", errors="replace").split()
            if len(parts) != 2 or parts[0] != "QUERY":
                sock.sendto(b"ERROR bad request", addr)
                continue
            domain = parts[1].lower()
            reply = "NOT_FOUND" if domain == MISSING else f"OK {OK_IP} {OK_TTL}"
            counter += 1
            print(f"Request #{counter}: {parts[1]} -> {reply}", flush=True)
            sock.sendto(reply.encode("utf-8"), addr)
    except KeyboardInterrupt:
        print("\nUpstream stopped.", flush=True)
    finally:
        sock.close()


if __name__ == "__main__":
    main()