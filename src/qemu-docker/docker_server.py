#!/usr/bin/env python3

import os
import socket
import subprocess
from tempfile import NamedTemporaryFile
import threading


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        with open("/tmp/template.elf", "rb") as f:
            binary_data = f.read()

            # Find 4 nops to replace
            nops = (
                binary_data.find(
                    b"\x0d\xc0\x31\x62"
                    + b"\x00\x40\x00\x7f" * 3
                    + b"\x00\xc0\x00\x7f"
                    + b"\x0b\xc0\x04\x6a"
                )
                + 4
            )

            self.binary_prefix = binary_data[:nops]
            self.binary_suffix = binary_data[nops + 16 :]

    def listen(self):
        self.sock.listen(10)
        while True:
            client, _address = self.sock.accept()
            threading.Thread(target=self.listenToClient, args=(client,)).start()

    def listenToClient(self, client):
        data = client.recv(16 + 4 * 21)
        if not data or len(data) < 16 + 4 * 21:
            client.send(b"CRASH")
            client.close()
            return

        binary_data = self.binary_prefix + data[:16] + self.binary_suffix
        input_data = data[16:]

        file = NamedTemporaryFile(delete=False)
        file.write(binary_data)
        os.chmod(file.name, 0o555)
        file.close()

        proc = subprocess.run(
            ["qemu-hexagon", file.name],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        l = proc.stdout
        print(l)
        client.send(l)
        client.close()

        os.remove(file.name)


def main():
    ThreadedServer("", int(os.getenv("SERVER_PORT", "9000"))).listen()


if __name__ == "__main__":
    main()
