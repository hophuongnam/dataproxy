#!/usr/bin/env python3
"""End-to-end check of dpt_server.py with a fake phone. Needs openssl on PATH.

  python3 server/test_dpt.py

The fake phone follows ReverseTunnel.kt: TLS with a SHA-256 pin, DPT1 hello,
ignore 0x00, ack 0x01, then serve one conversation (here: echo).
"""
import hashlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PUB, CLI = 18450, 18451
TOKEN = "s3cret-token"


def phone_link(pin, token=TOKEN):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PUB), 5))
    got = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
    if got != pin:
        s.close()
        raise ValueError("cert pin mismatch, server sent " + got)
    s.settimeout(5)
    s.sendall(f"DPT1 {token}\n".encode())
    return s


def read_ok(s):
    line = b""
    while not line.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            return line
        line += b
    return line


def wait_pair(s, ack=True):
    """Block until 0x01; returns the number of keepalives seen first."""
    keepalives = 0
    while True:
        b = s.recv(1)
        assert b, "relay closed an idle link"
        if b == b"\x00":
            keepalives += 1
            continue
        assert b == b"\x01", b
        if ack:
            s.sendall(b"\x01")
        return keepalives


def client(payload, timeout=10):
    c = socket.create_connection(("127.0.0.1", CLI), timeout)
    c.sendall(payload)
    return c


def main():
    tmp = tempfile.mkdtemp()
    cert, key, tok = (os.path.join(tmp, n) for n in ("cert.pem", "key.pem", "token.txt"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "1", "-subj", "/CN=dpt-test"], check=True, capture_output=True)
    with open(tok, "w") as f:
        f.write(TOKEN + "\n")
    with open(cert) as f:
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()

    srv = subprocess.Popen([sys.executable, os.path.join(HERE, "dpt_server.py"),
                            "--public", f"127.0.0.1:{PUB}", "--client", f"127.0.0.1:{CLI}",
                            "--cert", cert, "--key", key, "--token-file", tok,
                            "--keepalive", "1", "--pair-timeout", "2", "--ack-timeout", "1"],
                           stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(1)

        # Server prints the same pin the phone must enter.
        # (read later from stderr, after the process ends)

        # 1. Bad token: the relay closes without OK.
        bad = phone_link(pin, token="wrong")
        assert read_ok(bad) == b"", "bad token got a reply"
        print("ok  bad token is closed")

        # 2. Wrong pin: the phone refuses the relay.
        try:
            phone_link("00" * 32)
            raise AssertionError("wrong pin accepted")
        except ValueError as e:
            assert "mismatch" in str(e)
        print("ok  wrong pin is refused by the phone")

        # 3. No phone link: the client is closed after the pair timeout.
        t0 = time.time()
        c = client(b"hello")
        assert c.recv(10) == b"" and 1.5 < time.time() - t0 < 4
        print("ok  client with no phone is closed after %.1fs" % (time.time() - t0))

        # 4. Keepalive + pairing + splice both ways.
        p = phone_link(pin)
        assert read_ok(p) == b"OK\n"
        time.sleep(2.5)
        c = client(b"ping")
        ka = wait_pair(p)
        assert ka >= 2, ka
        assert p.recv(4) == b"ping"
        p.sendall(b"pong")
        assert c.recv(4) == b"pong"
        print(f"ok  paired after {ka} keepalives, bytes flow both ways")

        # 5. Phone closes: the client sees EOF.
        p.close()
        assert c.recv(10) == b""
        print("ok  phone close reaches the client as EOF")

        # 6. A link that never acks is skipped, the next one is used.
        live = phone_link(pin); assert read_ok(live) == b"OK\n"
        dead = phone_link(pin); assert read_ok(dead) == b"OK\n"   # newest, picked first
        time.sleep(0.2)
        c = client(b"x")
        wait_pair(dead, ack=False)
        wait_pair(live)
        assert live.recv(1) == b"x"
        print("ok  link with no ack is skipped")
        live.close(); dead.close(); c.close()

        # 7. An idle link the phone dropped leaves the pool.
        gone = phone_link(pin); assert read_ok(gone) == b"OK\n"
        gone.close()
        time.sleep(0.5)
        t0 = time.time()
        c = client(b"y")
        assert c.recv(1) == b"" and time.time() - t0 > 1.5
        print("ok  dropped idle link is not used")
    finally:
        srv.terminate()
        _, err = srv.communicate(timeout=5)
    assert f"cert pin (enter on the phone): {pin}" in err, err
    print("ok  server prints the pin")
    print("--- server log ---\n" + err)


if __name__ == "__main__":
    main()
