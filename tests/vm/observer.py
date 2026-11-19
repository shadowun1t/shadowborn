"""Synthetic TLS/DNS and HTTPS origin in the disposable observer namespace."""
import http.server
import os
import socket
import socketserver
import ssl
import struct
import threading


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise EOFError
    return data


class DNS(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            while True:
                length, = struct.unpack('!H', read_exact(self.rfile, 2))
                query = read_exact(self.rfile, length)
                end = 12
                while query[end]:
                    end += query[end] + 1
                end += 5
                kind = struct.unpack('!H', query[end-4:end-2])[0]
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('198.18.0.80') if kind == 1 else b''
                reply = query[:2] + struct.pack('!5H', 0x8180, 1, bool(answer), 0, 0) + query[12:end] + answer
                self.wfile.write(struct.pack('!H', len(reply)) + reply)
        except (EOFError, OSError):
            return


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(self.client_address[0])))
        self.end_headers()
        self.wfile.write(self.client_address[0].encode())

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net') or not os.path.exists('/dev/virtio-ports/shadowborn.test'):
        raise SystemExit('Observer requires disposable guest network namespace')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain('/root/fixture.crt', '/root/fixture.key')
    for address in ('9.9.9.9', '149.112.112.112'):
        dns = socketserver.ThreadingTCPServer((address, 853), DNS, bind_and_activate=False)
        dns.allow_reuse_address = True
        dns.server_bind()
        dns.server_activate()
        dns.socket = tls.wrap_socket(dns.socket, server_side=True)
        threading.Thread(target=dns.serve_forever, daemon=True).start()
    portal = http.server.ThreadingHTTPServer(('203.0.113.254', 443), Origin)
    portal.socket = tls.wrap_socket(portal.socket, server_side=True)
    threading.Thread(target=portal.serve_forever, daemon=True).start()
    http = http.server.ThreadingHTTPServer(('198.18.0.80', 443), Origin)
    http.socket = tls.wrap_socket(http.socket, server_side=True)
    http.serve_forever()
