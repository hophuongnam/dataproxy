#!/usr/bin/env python3
"""DataProxy reverse-tunnel relay (protocol DPT1). Python 3.11+, stdlib only.

Phones dial in over TLS on --public and park idle links. A SOCKS5 client that
connects to --client (plain TCP, keep it on a private network) is spliced onto
one of those links and talks SOCKS5 to the phone, auth included.

Protocol, per link:
  phone  -> relay   b"DPT1 <token>\\n"
  relay  -> phone   b"OK\\n", or close on a bad token
  relay  -> phone   0x00 every --keepalive seconds while idle
  relay  -> phone   0x01 when a client is waiting
  phone  -> relay   0x01 ack, then raw bytes both ways until either side closes

Make a self-signed cert (the phone pins it, no CA involved):
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \\
    -keyout key.pem -out cert.pem -days 3650 -subj /CN=dataproxy-tunnel

Run:
  python3 dpt_server.py --public 0.0.0.0:8450 --client 100.85.71.76:8451 \\
    --cert cert.pem --key key.pem --token-file token.txt
"""
import argparse
import asyncio
import hashlib
import hmac
import logging
import socket
import ssl
import time

log = logging.getLogger("dpt")


class EofReader(asyncio.StreamReader):
    """Turns a transport error (say a RST) into EOF, after the buffered data.

    The stock reader raises a stored error before it returns data it already
    holds, which loses the tail of a reply. A TCP splice has no use for the
    error anyway.
    """

    def set_exception(self, exc):
        self.feed_eof()


class Tls:
    """Server-side TLS over a plain stream, via ssl.MemoryBIO.

    Not asyncio's own SSL transport: that one drops data decrypted in the same
    batch as a later SSL error (CPython 3.12 to 3.14, _do_read__copied). A JVM
    peer closing TLS 1.3 sends data + user_canceled + close_notify at once and
    triggers exactly that, so the last reply bytes vanished. Here each read()
    returns at most one record, and an error only ends the stream after.
    """

    def __init__(self, ctx, reader, writer):
        self.reader, self.writer = reader, writer
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.inc, self.out, server_side=True)
        self.eof = False

    def _flush(self):
        if data := self.out.read():
            self.writer.write(data)

    async def _fill(self):
        self._flush()
        await self.writer.drain()
        data = await self.reader.read(65536)
        if data:
            self.inc.write(data)
        return bool(data)

    async def handshake(self):
        while True:
            try:
                self.obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                if not await self._fill():
                    raise ConnectionError("EOF during TLS handshake")
        await self.drain()

    async def read(self, n=65536):
        while not self.eof:
            try:
                data = self.obj.read(n)
                self._flush()  # a read can queue a post-handshake reply
                if not data:
                    self.eof = True  # close_notify
                return data
            except ssl.SSLWantReadError:
                if not await self._fill():
                    self.eof = True
            except ssl.SSLError:
                self.eof = True
        return b""

    def write(self, data):
        self.obj.write(data)
        self._flush()

    async def drain(self):
        self._flush()
        await self.writer.drain()

    def close(self):
        try:
            self.obj.unwrap()  # queue close_notify, best effort
        except ssl.SSLError:
            pass
        self._flush()
        self.writer.close()


class Link:
    def __init__(self, tls, peer):
        self.tls, self.peer = tls, peer
        self.watch = None  # task that reads (to spot death) and sends keepalives


class Relay:
    def __init__(self, ctx, token, keepalive, pair_timeout, ack_timeout):
        self.ctx = ctx
        self.hello = b"DPT1 " + token.encode() + b"\n"
        self.keepalive = keepalive
        self.pair_timeout = pair_timeout
        self.ack_timeout = ack_timeout
        self.idle = []  # newest last: after a network change the fresh links are the live ones
        self.arrived = asyncio.Event()

    # ------------------------------------------------------------ phone side

    async def on_phone(self, reader, writer):
        tune(writer)
        peer = writer.get_extra_info("peername")
        tls = Tls(self.ctx, reader, writer)
        try:
            line = await asyncio.wait_for(self.read_hello(tls), 15)
        except Exception as e:
            log.info("phone %s dropped before hello: %r", peer, e)
            writer.close()
            return
        if not hmac.compare_digest(line, self.hello):
            log.info("phone %s rejected: bad hello", peer)
            tls.close()
            return
        tls.write(b"OK\n")
        await tls.drain()
        link = Link(tls, peer)
        self.idle.append(link)
        link.watch = asyncio.create_task(self.watch(link))
        self.arrived.set()
        log.info("phone %s link up, idle=%d", peer, len(self.idle))

    async def read_hello(self, tls):
        await tls.handshake()
        line = b""
        while not line.endswith(b"\n") and len(line) <= 512:
            b = await tls.read(1)
            if not b:
                break
            line += b
        return line

    async def watch(self, link):
        # The phone sends nothing while idle, so any read result means it is gone.
        try:
            while True:
                try:
                    await asyncio.wait_for(link.tls.read(1), self.keepalive)
                    break
                except TimeoutError:
                    link.tls.write(b"\x00")
                    await link.tls.drain()
        except asyncio.CancelledError:
            raise  # being paired, the link stays open
        except Exception:
            pass
        self.drop(link, "idle link lost")

    def drop(self, link, why):
        if link in self.idle:
            self.idle.remove(link)
        link.tls.close()
        log.info("phone %s %s, idle=%d", link.peer, why, len(self.idle))

    # ----------------------------------------------------------- client side

    async def take(self):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.pair_timeout
        while (left := deadline - loop.time()) > 0:
            if not self.idle:
                self.arrived.clear()
                try:
                    await asyncio.wait_for(self.arrived.wait(), left)
                except TimeoutError:
                    return None
                continue
            link = self.idle.pop()
            link.watch.cancel()
            try:
                await link.watch
            except asyncio.CancelledError:
                pass
            try:
                link.tls.write(b"\x01")
                await link.tls.drain()
                ack = await asyncio.wait_for(link.tls.read(1), min(self.ack_timeout, left))
                if ack == b"\x01":
                    return link
            except Exception:
                pass
            self.drop(link, "no ack, skipped")
        return None

    async def on_client(self, reader, writer):
        tune(writer)
        peer = writer.get_extra_info("peername")
        link = await self.take()
        if link is None:
            log.info("client %s: no phone link within %ss, closed", peer, self.pair_timeout)
            writer.close()
            return
        log.info("client %s paired with phone %s, idle=%d", peer, link.peer, len(self.idle))
        t0 = time.monotonic()
        # No half-close: the phone's TLS stack cannot carry one, so the first
        # EOF ends both ways.
        pipes = [asyncio.create_task(pipe(reader, link.tls)),
                 asyncio.create_task(pipe(link.tls, writer))]
        await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        for t in pipes:
            t.cancel()
        writer.close()
        link.tls.close()
        log.info("client %s closed after %.1fs", peer, time.monotonic() - t0)


async def pipe(src, dst):
    try:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()
    except Exception:
        pass


def tune(writer):
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # Linux only: fail a write unacked for 60 s, so a phone that vanished
    # without a FIN is dropped in a minute, not after ~15 min of retries.
    if hasattr(socket, "TCP_USER_TIMEOUT"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 60_000)


def hostport(s):
    host, _, port = s.rpartition(":")
    return host.strip("[]"), int(port)


def cert_pin(path):
    with open(path) as f:
        pem = f.read()
    first = pem[: pem.index("-----END CERTIFICATE-----") + 25]
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(first)).hexdigest()


async def serve(cb, host, port):
    loop = asyncio.get_running_loop()
    return await loop.create_server(
        lambda: asyncio.StreamReaderProtocol(EofReader(), cb), host, port)


async def main():
    ap = argparse.ArgumentParser(description="DataProxy reverse-tunnel relay")
    ap.add_argument("--public", default="0.0.0.0:8450", help="TLS listener for phones")
    ap.add_argument("--client", default="127.0.0.1:8451", help="plain TCP listener for SOCKS5 clients")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--keepalive", type=float, default=25)
    ap.add_argument("--pair-timeout", type=float, default=5)
    ap.add_argument("--ack-timeout", type=float, default=3)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    with open(a.token_file) as f:
        token = f.read().strip()
    if not token:
        raise SystemExit("token file is empty")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(a.cert, a.key)

    relay = Relay(ctx, token, a.keepalive, a.pair_timeout, a.ack_timeout)
    phones = await serve(relay.on_phone, *hostport(a.public))
    clients = await serve(relay.on_client, *hostport(a.client))
    log.info("cert pin (enter on the phone): %s", cert_pin(a.cert))
    log.info("phones on %s (TLS), SOCKS5 clients on %s", a.public, a.client)
    async with phones, clients:
        await asyncio.gather(phones.serve_forever(), clients.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
