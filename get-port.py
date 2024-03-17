import socket


def next_available_port():
    """Find the next available port number for localhost."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("localhost", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port
    except OSError:
        raise IOError("no free ports")


if __name__ == "__main__":
    print(next_available_port())
