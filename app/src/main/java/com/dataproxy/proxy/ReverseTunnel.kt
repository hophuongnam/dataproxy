package com.dataproxy.proxy

import android.util.Log
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

/**
 * Reverse tunnel: the phone dials OUT to a relay (server/dpt_server.py) so
 * clients can reach the proxy when the phone is behind NAT on any network.
 *
 * Protocol (DPT1), one TCP + TLS link per pool slot:
 *   phone  -> server  "DPT1 <token>\n"
 *   server -> phone   "OK\n" (or close)
 *   server -> phone   0x00 every 25 s while idle (keepalive, ignored)
 *   server -> phone   0x01 = a client is waiting
 *   phone  -> server  0x01 = ack, then the link carries one SOCKS5 conversation
 *
 * The ack lets the server skip a link that died silently (phone changed
 * networks) and try the next one, instead of pairing a client with a corpse.
 *
 * Links go over the DEFAULT network (Wi-Fi or mobile, whatever is up) on
 * purpose, with no Network.bindSocket. Only the control path does this: the
 * paired socket goes to [Socks5Server.adopt], and every target connection
 * still egresses via cellular in Socks5Connection.openRemote.
 *
 * The server cert is self-signed and checked by SHA-256 pin of its DER bytes,
 * there is no CA and no hostname check.
 */
class ReverseTunnel(
    private val host: String,
    private val port: Int,
    private val token: String,
    pin: String,
    private val poolSize: Int,
    private val onPaired: (Socket) -> Unit,
    private val onStatus: (String) -> Unit,
) {
    private val pin = pin.replace(":", "").trim().lowercase()

    @Volatile private var running = true
    @Volatile private var lastError = ""
    private val up = AtomicInteger(0)

    /** Every socket not yet handed off, so [stop] can unblock its thread. */
    private val open = ConcurrentHashMap.newKeySet<Socket>()

    private val tls = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(PinTrustManager(this@ReverseTunnel.pin)), null)
    }.socketFactory

    private val workers = List(poolSize) { i ->
        thread(name = "tunnel-$i", isDaemon = true) { loop() }
    }

    init { publish() }

    fun stop() {
        running = false
        workers.forEach { it.interrupt() }
        open.forEach { runCatching { it.close() } }
    }

    private fun loop() {
        var backoff = MIN_BACKOFF_MS
        while (running) {
            try {
                val link = dial { backoff = MIN_BACKOFF_MS }
                // Loop straight back to dial a replacement, so the pool stays at N.
                onPaired(link)
                continue
            } catch (e: Exception) {
                if (!running) break
                lastError = e.message ?: e.javaClass.simpleName
                Log.d(TAG, "link failed: $lastError")
                publish()
            }
            try { Thread.sleep(backoff) } catch (_: InterruptedException) { break }
            backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
    }

    /** Connect, authenticate, and block until the server pairs this link. */
    private fun dial(onAuthed: () -> Unit): Socket {
        val raw = Socket()
        open.add(raw)
        var counted = false
        try {
            if (!running) throw IOException("stopped")
            // Resolves and connects on the default network, deliberately (see
            // class doc). This is the tunnel's own control path, not target DNS.
            raw.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            raw.tcpNoDelay = true
            raw.keepAlive = true
            val link = tls.createSocket(raw, host, port, true) as SSLSocket
            // Covers the handshake, the OK line, and idle silence alike.
            link.soTimeout = IDLE_TIMEOUT_MS
            link.startHandshake()
            val out = link.outputStream
            val inp = link.inputStream
            out.write("DPT1 $token\n".toByteArray(Charsets.UTF_8))
            out.flush()
            if (readLine(inp) != "OK") throw IOException("server rejected the token")
            onAuthed()
            up.incrementAndGet(); counted = true
            lastError = ""
            publish()
            // Single unbuffered byte reads: the SOCKS5 greeting follows the
            // ack on this same stream, and a buffered reader would swallow it.
            while (true) {
                when (val b = inp.read()) {
                    0x00 -> continue
                    0x01 -> {
                        out.write(0x01); out.flush()
                        open.remove(raw)
                        return link
                    }
                    -1 -> throw IOException("server closed the link")
                    else -> throw IOException("unexpected byte $b")
                }
            }
        } catch (e: Exception) {
            open.remove(raw)
            runCatching { raw.close() }
            throw e
        } finally {
            if (counted) { up.decrementAndGet(); publish() }
        }
    }

    private fun readLine(inp: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 16) {
            val b = inp.read()
            if (b < 0 || b == '\n'.code) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    private fun publish() {
        if (!running) return
        val n = up.get()
        onStatus(
            // 0 up with no error is normal under load: every link is paired.
            if (n > 0 || lastError.isEmpty()) "$n of $poolSize links up"
            else "Connecting. Last error: $lastError"
        )
    }

    private class PinTrustManager(private val pin: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("client certs not accepted")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val got = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                .joinToString("") { "%02x".format(it) }
            // The observed pin goes into the message on purpose: the status
            // line is the only debug channel on a phone with no adb.
            if (got != pin) throw CertificateException("cert pin mismatch, server sent $got")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    companion object {
        private const val TAG = "ReverseTunnel"
        private const val CONNECT_TIMEOUT_MS = 15_000
        // ponytail: 3 missed keepalives (server sends one every 25 s).
        private const val IDLE_TIMEOUT_MS = 75_000
        private const val MIN_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 30_000L
        const val DEFAULT_PORT = 8450
        const val DEFAULT_POOL = 4
    }
}
