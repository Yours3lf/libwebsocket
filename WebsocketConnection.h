#pragma once

#include "libsocket/Socket.h"
#include "libsocket/EventWait.h"
#include "WebsocketMessage.h"
#include "TLSutil.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <cctype>

#ifdef Z_SOLO
#error "Z_SOLO defined, but we use standard malloc"
#endif
#include "zlib/zlib.h"

// Outgoing data frames are split at this size (RFC 6455 section 5.4). 64KiB is
// the largest payload many intermediaries accept as a single frame.
static const uint32_t kMaxFramePayload = 64u * 1024u;
// Reassembled message cap. Media blobs in Media.h run about 2-3MB, so 16MiB
// leaves room for that payload plus the binary envelope.
static const uint32_t kMaxMessageBytes = 16u * 1024u * 1024u;
// HTTP upgrade request cap. A browser handshake is a few hundred bytes.
static const uint32_t kMaxHandshakeBytes = 16u * 1024u;
// Bytes pulled from the socket on one readable event.
static const uint32_t kReadChunkBytes = 16u * 1024u;
// How long the handshake thread waits for the rest of the HTTP request.
static const int kHandshakeTimeoutMs = 10000;
// RFC 6455 section 7.1.1: after sending Close, wait for the peer Close.
static const int kCloseHandshakeTimeoutMs = 5000;
// Idle time before the server sends a Ping, and the time allowed for a Pong.
static const int kKeepaliveIntervalMs = 30000;
// Not a wire code. Local close finished; the app already requested it, so the
// server removes the slot without a second FRAME_CLOSE.
static const int kCloseQuiet = -6;

// RFC 6455 section 7.4.1 status codes we send.
static const uint16_t kCloseNormal = 1000;       // normal closure
static const uint16_t kCloseGoingAway = 1001;    // endpoint going away (missed pong)
static const uint16_t kCloseProtocol = 1002;     // protocol error
static const uint16_t kCloseBadPayload = 1007;   // invalid UTF-8 text, or close reason
static const uint16_t kCloseTooBig = 1009;       // message too big
// RFC 6455 section 7.4.1: must not appear in a Close frame on the wire.
static const uint16_t kCloseReserved = 1004;
static const uint16_t kCloseNoStatus = 1005;
static const uint16_t kCloseAbnormal = 1006;
static const uint16_t kCloseTlsFailure = 1015;
// 1016-2999 are reserved for future library codes. 3000+ is the private range.
static const uint16_t kCloseLibraryStart = 1016;
static const uint16_t kClosePrivateStart = 3000;

static void freeDeflateStream(z_stream* stream)
{
    if (!stream)
        return;
    deflateEnd(stream);
    free(stream);
}

static void freeInflateStream(z_stream* stream)
{
    if (!stream)
        return;
    inflateEnd(stream);
    free(stream);
}

static bool isValidUtf8(const char* data, size_t len)
{
    size_t i = 0;
    while (i < len)
    {
        unsigned char c = (unsigned char)data[i];
        size_t need = 0;
        if (c <= 0x7F)
        {
            i++;
            continue;
        }
        else if ((c & 0xE0) == 0xC0)
        {
            if (c < 0xC2)
                return false;
            need = 2;
        }
        else if ((c & 0xF0) == 0xE0)
            need = 3;
        else if ((c & 0xF8) == 0xF0)
        {
            if (c > 0xF4)
                return false;
            need = 4;
        }
        else
            return false;

        if (i + need > len)
            return false;
        for (size_t j = 1; j < need; ++j)
        {
            if (((unsigned char)data[i + j] & 0xC0) != 0x80)
                return false;
        }
        if (need == 3)
        {
            unsigned char c1 = (unsigned char)data[i + 1];
            if (c == 0xE0 && c1 < 0xA0)
                return false;
            if (c == 0xED && c1 >= 0xA0)
                return false;
        }
        if (need == 4)
        {
            unsigned char c1 = (unsigned char)data[i + 1];
            if (c == 0xF0 && c1 < 0x90)
                return false;
            if (c == 0xF4 && c1 >= 0x90)
                return false;
        }
        i += need;
    }
    return true;
}

static std::string asciiLower(const std::string& in)
{
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (char)tolower((unsigned char)out[i]);
    return out;
}

static std::string trimWs(const std::string& in)
{
    size_t b = 0;
    while (b < in.size() && (in[b] == ' ' || in[b] == '\t'))
        b++;
    size_t e = in.size();
    while (e > b && (in[e - 1] == ' ' || in[e - 1] == '\t' || in[e - 1] == '\r'))
        e--;
    return in.substr(b, e - b);
}

static bool headerTokenHas(const std::string& value, const char* token)
{
    std::string lower = asciiLower(value);
    std::string want = asciiLower(token);
    size_t pos = 0;
    while (pos < lower.size())
    {
        size_t comma = lower.find(',', pos);
        if (comma == std::string::npos)
            comma = lower.size();
        if (trimWs(lower.substr(pos, comma - pos)) == want)
            return true;
        pos = comma + 1;
    }
    return false;
}

static void splitHeader(const std::string& header, std::vector<std::string>& lines)
{
    std::string copy = header;
    std::string delimiter = "\r\n";
    size_t pos = 0;
    while ((pos = copy.find(delimiter)) != std::string::npos)
    {
        std::string line = copy.substr(0, pos);
        lines.push_back(line);
        copy = copy.substr(pos + 2, std::string::npos);
    }
}

static std::string getHandshakeResponseKey(const std::string& webSocketKey)
{
#ifdef _WIN32
    HCRYPTPROV cryptoProvider = 0;
    CryptAcquireContext(&cryptoProvider,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT);

    HCRYPTHASH hashProvider = 0;
    CryptCreateHash(cryptoProvider, CALG_SHA1, 0, 0, &hashProvider);

    CryptHashData(hashProvider, (const uint8_t*)webSocketKey.data(), webSocketKey.length(), 0);

    DWORD hashSize = 0;
    DWORD hashSizeBytes = sizeof(hashSize);
    CryptGetHashParam(hashProvider, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeBytes, 0);

    std::vector<uint8_t> hashBytes(hashSize);
    DWORD hashBytesSize = hashSize;
    CryptGetHashParam(hashProvider, HP_HASHVAL, hashBytes.data(), &hashBytesSize, 0);

    std::vector<char> hashStrBuf(32);
    DWORD hashStrBufLen = 32;
    CryptBinaryToStringA(hashBytes.data(), hashBytesSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, hashStrBuf.data(), &hashStrBufLen);

    CryptReleaseContext(cryptoProvider, 0);
    CryptDestroyHash(hashProvider);

    return std::string(hashStrBuf.data());
#else
    // SHA1(..., nullptr) writes a process-wide static buffer and races the handshake threads.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)webSocketKey.data(), webSocketKey.length(), hash);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, hash, SHA_DIGEST_LENGTH);
    BIO_flush(b64);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
#endif
}

/**
Websocket Frame format:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
**/
union websocketHeader
{
    uint16_t _data;
    struct
    {
        union
        {
            uint8_t _second;
            struct
            {
                uint8_t opcode : 4;
                bool rsv3 : 1;
                bool rsv2 : 1;
                bool rsv1 : 1;
                bool fin : 1;
            };
        };
        union
        {
            uint8_t _first;
            struct
            {
                uint8_t payloadLen : 7;
                bool masked : 1;
            };
        };
    };
};
static_assert(sizeof(websocketHeader) == 2, "websocket header is two bytes on the wire");

static bool parseWindowBits(const std::string& raw, int& bits)
{
    if (raw.empty())
    {
        bits = 15;
        return true;
    }
    if (raw.size() > 2)
        return false;
    int v = 0;
    for (size_t i = 0; i < raw.size(); ++i)
    {
        if (raw[i] < '0' || raw[i] > '9')
            return false;
        v = v * 10 + (raw[i] - '0');
    }
    if (v < 8 || v > 15)
        return false;
    bits = v;
    return true;
}

class websocketConnection
{
    class socket s;
    TLSsession tlsSession;
    bool useTlsFlag = false;

    std::vector<char> readBuf;
    size_t readPos = 0;
    std::vector<char> pendingOut;

    bool assembling = false;
    frameType assembleType = FRAME_TEXT;
    bool assembleCompressed = false;
    std::vector<char> assembleBuf;

    bool enableDeflate = false;
    bool compressorStream = true;
    bool deCompressorStream = true;
    // zlib windowBits 15 is a 32KB window, the RFC 7692 default.
    int compressorBits = 15;
    int deCompressorBits = 15;
    // Below this, deflate often grows the payload or saves too little to be worth it.
    static constexpr uint32_t minBufferSizeForCompression = 256;
    std::unique_ptr<z_stream, void(*)(z_stream*)> compressor{nullptr, freeDeflateStream};
    std::unique_ptr<z_stream, void(*)(z_stream*)> deCompressor{nullptr, freeInflateStream};
    static constexpr int compressionLevel = Z_BEST_COMPRESSION;
    std::vector<char> compressionBuf;
    std::vector<char> deCompressionBuf;

    std::string url;
    std::string host;
    std::string origin;
    std::vector<std::string> subprotocols;

    uint32_t maxFramePayload = kMaxFramePayload;
    uint32_t maxMessageBytes = kMaxMessageBytes;

    bool closeFrameSent = false;
    bool localClose = false;
    bool sawPeerClose = false;
    std::chrono::steady_clock::time_point closeDeadline{};
    std::chrono::steady_clock::time_point lastActivity = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point pingSent{};
    bool awaitingPong = false;

    const static std::string magicString;

    void compactRead()
    {
        if (readPos == 0)
            return;
        if (readPos >= readBuf.size())
        {
            readBuf.clear();
            readPos = 0;
            return;
        }
        readBuf.erase(readBuf.begin(), readBuf.begin() + readPos);
        readPos = 0;
    }

    size_t buffered() const
    {
        return readBuf.size() - readPos;
    }

    int recvSome(char* buf, int len, bool useTLS)
    {
        if (useTLS)
            return tlsSession.receiveMessage(buf, len, true);
        return s.receive(buf, len, true);
    }

    int sendSome(const char* buf, int len, bool useTLS)
    {
        if (useTLS)
            return tlsSession.sendMessage(buf, len);
        return s.send(buf, len);
    }

    int pullBytes(bool useTLS)
    {
        if (!s.isValid())
            return socket::kPeerClosed;
        if (readBuf.size() > maxMessageBytes + 14)
            return fail(kCloseTooBig, useTLS);

        std::vector<char> chunk(kReadChunkBytes);
        int n = recvSome(chunk.data(), (int)chunk.size(), useTLS);
        if (n == socket::kWouldBlock || n == 0)
            return 0;
        if (n < 0)
            return n;
        readBuf.insert(readBuf.end(), chunk.begin(), chunk.begin() + n);
        return n;
    }

    void writeFrame(std::vector<char>& out, bool fin, bool rsv1, uint8_t opcode, const char* data, size_t len)
    {
        websocketHeader h = {};
        h.fin = fin;
        h.rsv1 = rsv1;
        h.opcode = opcode;
        h.masked = false; // server frames are not masked
        if (len < 126)
            h.payloadLen = (uint8_t)len;
        else if (len <= 65535)
            h.payloadLen = 126;
        else
            h.payloadLen = 127;

        setRawData(out, &h);
        if (h.payloadLen == 126)
        {
            uint16_t extended = swapEndianness((uint16_t)len);
            setRawData(out, &extended);
        }
        else if (h.payloadLen == 127)
        {
            uint64_t extended = swapEndianness((uint64_t)len);
            setRawData(out, &extended);
        }
        if (data && len)
            setRawData(out, data, (uint32_t)len);
    }

    int flushPendingSend(bool useTLS)
    {
        while (!pendingOut.empty())
        {
            int n = sendSome(pendingOut.data(), (int)pendingOut.size(), useTLS);
            if (n == socket::kWouldBlock)
                return socket::kWouldBlock;
            if (n < 0)
                return n;
            if (n == 0)
                return -1;
            pendingOut.erase(pendingOut.begin(), pendingOut.begin() + n);
        }
        return 0;
    }

    int queueFrame(bool fin, bool rsv1, uint8_t opcode, const char* data, size_t len, bool useTLS)
    {
        writeFrame(pendingOut, fin, rsv1, opcode, data, len);
        return flushPendingSend(useTLS);
    }

    int sendCloseFrame(uint16_t code, bool useTLS)
    {
        if (closeFrameSent || !s.isValid())
            return 0;
        uint16_t codeBE = swapEndianness(code);
        std::vector<char> body;
        setRawData(body, &codeBE);
        closeFrameSent = true;
        return queueFrame(true, false, FRAME_CLOSE, body.data(), body.size(), useTLS);
    }

    int fail(uint16_t code, bool useTLS)
    {
        std::cerr << "Websocket protocol close " << code << std::endl;
        sendCloseFrame(code, useTLS);
        return -2;
    }

    bool need(size_t n) const
    {
        return buffered() >= n;
    }

    int inflateMessage(size_t plainStart, std::vector<char>& dest)
    {
        if (!deCompressor)
        {
            std::cerr << "decompressor not inited" << std::endl;
            return -1;
        }

        // RFC 7692 strips the 00 00 ff ff sync-flush tail. Put it back before inflate.
        std::vector<char> appendix = {0x00, 0x00, (char)0xff, (char)0xff};
        dest.insert(dest.end(), appendix.begin(), appendix.end());

        // reasonable starting decompression buf size
        deCompressionBuf.resize((dest.size() - plainStart) * 3 + 1024);
        uint32_t decompressedSize = 0;
        deCompressor->next_in = (unsigned char*)dest.data() + plainStart;
        deCompressor->avail_in = (uInt)(dest.size() - plainStart);
        deCompressor->next_out = (unsigned char*)deCompressionBuf.data();
        deCompressor->avail_out = (uInt)deCompressionBuf.size();

        while (true)
        {
            uInt before = deCompressor->avail_out;
            int res = inflate(deCompressor.get(), Z_SYNC_FLUSH);
            decompressedSize += before - deCompressor->avail_out;
            if (res == Z_BUF_ERROR || (res == Z_OK && deCompressor->avail_out == 0))
            {
                uint32_t oldSize = (uint32_t)deCompressionBuf.size();
                // double decompression buffer size and try again
                deCompressionBuf.resize(deCompressionBuf.size() * 2);
                deCompressor->next_out = (Bytef*)deCompressionBuf.data() + oldSize;
                deCompressor->avail_out = (uInt)(deCompressionBuf.size() - oldSize);
            }
            else if ((res == Z_OK || res == Z_STREAM_END) && deCompressor->avail_in == 0)
            {
                // status code okay and all input bytes consumed
                break;
            }
            else
            {
                std::cerr << "Error while running zlib decompression: " << res << std::endl;
                return -1;
            }
        }

        // on success copy the decompressed data to the output message
        dest.resize(plainStart + decompressedSize);
        memcpy(dest.data() + plainStart, deCompressionBuf.data(), decompressedSize);

        if (!deCompressorStream)
        {
            if (inflateReset(deCompressor.get()) != Z_OK)
            {
                std::cerr << "failed resetting decompressor" << std::endl;
                return -1;
            }
        }
        return 0;
    }

    int finishDataMessage(websocketMessage& m, bool useTLS)
    {
        if (assembleCompressed)
        {
            if (inflateMessage(0, assembleBuf) != 0)
                return fail(kCloseProtocol, useTLS);
        }
        if (assembleType == FRAME_TEXT && !isValidUtf8(assembleBuf.data(), assembleBuf.size()))
            return fail(kCloseBadPayload, useTLS);
        if (assembleBuf.size() > maxMessageBytes)
            return fail(kCloseTooBig, useTLS);

        m.type = assembleType;
        m.buf.swap(assembleBuf);
        assembleBuf.clear();
        assembling = false;
        assembleCompressed = false;
        return (int)m.buf.size() > 0 ? (int)m.buf.size() : 1;
    }

    // One complete frame, or 0 if the buffer does not hold it yet.
    // Positive: an application data message is in m.
    // Negative: the connection is done.
    int parseOne(websocketMessage& m, bool useTLS)
    {
        while (true)
        {
            compactRead();
            if (!need(sizeof(websocketHeader)))
                return 0;

            uint32_t off = (uint32_t)readPos;
            websocketHeader h = {};
            derefRawData(getRawData<websocketHeader>(readBuf, off), h);
            bool fin = h.fin;
            bool rsv1 = h.rsv1;
            bool rsv2 = h.rsv2;
            bool rsv3 = h.rsv3;
            uint8_t opcode = h.opcode;
            bool masked = h.masked;
            uint64_t payloadLen = h.payloadLen;
            size_t header = sizeof(websocketHeader);

            if ((opcode >= 0x3 && opcode <= 0x7) || (opcode >= 0xB && opcode <= 0xF))
                return fail(kCloseProtocol, useTLS);
            if (rsv2 || rsv3)
                return fail(kCloseProtocol, useTLS);

            bool control = opcode >= 0x8;
            if (control && !fin)
                return fail(kCloseProtocol, useTLS);

            if (payloadLen == 126)
            {
                if (!need(sizeof(websocketHeader) + sizeof(uint16_t)))
                    return 0;
                uint16_t extended = 0;
                derefRawData(getRawData<uint16_t>(readBuf, off), extended);
                payloadLen = swapEndianness(extended);
                // 126 is only legal when the length does not fit in 7 bits.
                if (payloadLen < 126)
                    return fail(kCloseProtocol, useTLS);
                header = sizeof(websocketHeader) + sizeof(uint16_t);
            }
            else if (payloadLen == 127)
            {
                if (!need(sizeof(websocketHeader) + sizeof(uint64_t)))
                    return 0;
                uint64_t extended = 0;
                derefRawData(getRawData<uint64_t>(readBuf, off), extended);
                payloadLen = swapEndianness(extended);
                // The high bit of a 64-bit length must be 0 (RFC 6455 section 5.2).
                if (payloadLen & (1ull << 63))
                    return fail(kCloseProtocol, useTLS);
                if (payloadLen <= 65535)
                    return fail(kCloseProtocol, useTLS);
                header = sizeof(websocketHeader) + sizeof(uint64_t);
            }

            if (!masked)
                return fail(kCloseProtocol, useTLS);
            if (control && payloadLen > 125)
                return fail(kCloseProtocol, useTLS);
            if (payloadLen > maxMessageBytes)
                return fail(kCloseTooBig, useTLS);

            size_t total = header + 4 + (size_t)payloadLen;
            if (total < header)
                return fail(kCloseTooBig, useTLS);
            if (!need(total))
                return 0;

            uint8_t mask[4];
            for (int i = 0; i < 4; ++i)
            {
                mask[i] = {};
                derefRawData(getRawData<uint8_t>(readBuf, off), mask[i]);
            }

            std::vector<char> decoded((size_t)payloadLen);
            if (payloadLen > 0)
            {
                const char* encoded = getRawData<char>(readBuf, off, (uint32_t)payloadLen);
                if (!encoded)
                    return fail(kCloseProtocol, useTLS);
                for (uint64_t i = 0; i < payloadLen; ++i)
                    decoded[(size_t)i] = (char)(encoded[i] ^ mask[i % 4]);
            }
            readPos = off;

            lastActivity = std::chrono::steady_clock::now();

            if (opcode == FRAME_CLOSE)
                return handleClosePayloadWas(decoded, useTLS);
            if (opcode == FRAME_PING)
            {
                websocketMessage pong;
                pong.type = FRAME_PONG;
                pong.wantCompression = false;
                pong.buf.swap(decoded);
                int rc = sendWebsocketMessage(pong, useTLS);
                if (rc < 0 && rc != socket::kWouldBlock)
                    return rc;
                continue;
            }
            if (opcode == FRAME_PONG)
            {
                awaitingPong = false;
                continue;
            }

            bool first = !assembling;
            if (rsv1 && (!enableDeflate || !first || control))
                return fail(kCloseProtocol, useTLS);
            if (!enableDeflate && rsv1)
                return fail(kCloseProtocol, useTLS);

            if (!assembling)
            {
                if (opcode != FRAME_TEXT && opcode != FRAME_BINARY)
                    return fail(kCloseProtocol, useTLS);
                assembling = true;
                assembleType = (frameType)opcode;
                assembleCompressed = rsv1;
                assembleBuf.clear();
            }
            else
            {
                if (opcode != FRAME_CONTINUATION)
                    return fail(kCloseProtocol, useTLS);
                if (rsv1)
                    return fail(kCloseProtocol, useTLS);
            }

            if (assembleBuf.size() + decoded.size() > maxMessageBytes)
                return fail(kCloseTooBig, useTLS);
            assembleBuf.insert(assembleBuf.end(), decoded.begin(), decoded.end());

            if (fin)
                return finishDataMessage(m, useTLS);
        }
    }

    int handleClosePayloadWas(std::vector<char>& decoded, bool useTLS)
    {
        size_t len = decoded.size();
        if (len == 1)
            return fail(kCloseProtocol, useTLS);
        if (len >= 2)
        {
            uint32_t codeOff = 0;
            uint16_t codeBE = 0;
            derefRawData(getRawData<uint16_t>(decoded, codeOff), codeBE);
            uint16_t code = swapEndianness(codeBE);
            if (code < kCloseNormal || code == kCloseReserved || code == kCloseNoStatus ||
                code == kCloseAbnormal || code == kCloseTlsFailure ||
                (code >= kCloseLibraryStart && code < kClosePrivateStart))
                return fail(kCloseProtocol, useTLS);
            if (len > 2 && !isValidUtf8(decoded.data() + 2, len - 2))
                return fail(kCloseBadPayload, useTLS);
        }
        sawPeerClose = true;
        sendCloseFrame(kCloseNormal, useTLS);
        return localClose ? kCloseQuiet : -3;
    }

    bool compressPayload(const char* in, size_t inLen, const char*& out, size_t& outLen)
    {
        compressionBuf.resize(compressBound(inLen));
        compressor->next_out = (unsigned char*)compressionBuf.data();
        compressor->avail_out = (uInt)compressionBuf.size();
        std::vector<unsigned char> raw(reinterpret_cast<const unsigned char *>(in),
            reinterpret_cast<const unsigned char *>(in) + inLen);
        compressor->next_in = raw.data();
        compressor->avail_in = (uInt)inLen;

        int flushMode = Z_SYNC_FLUSH;
        int res = deflate(compressor.get(), flushMode);
        if (res < 0)
        {
            std::cerr << "websocket message compression res: " << res << std::endl;
            return false;
        }
        if (compressor->avail_in > 0 || compressor->avail_out == 0)
        {
            std::cerr << "couldn't deflate all input in one go" << std::endl;
            return false;
        }

        size_t produced = compressionBuf.size() - compressor->avail_out;
        bool hasTail = produced >= 4 &&
            (unsigned char)compressionBuf[produced - 4] == 0x00 &&
            (unsigned char)compressionBuf[produced - 3] == 0x00 &&
            (unsigned char)compressionBuf[produced - 2] == 0xFF &&
            (unsigned char)compressionBuf[produced - 1] == 0xFF;
        if (hasTail)
            produced -= 4;

        if (!compressorStream)
        {
            if (deflateReset(compressor.get()) != Z_OK)
            {
                std::cerr << "failed resetting compressor state" << std::endl;
                return false;
            }
        }

        out = compressionBuf.data();
        outLen = produced;
        return true;
    }

    bool sendHttp(const std::string& msg, bool useTLS)
    {
        int n = sendSome(msg.data(), (int)msg.size(), useTLS);
        return n >= 0 && (size_t)n == msg.size();
    }

    void sendHttp400(bool useTLS)
    {
        const char* msg =
            "HTTP/1.1 400 Bad Request\r\n"
            "Connection: close\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        sendSome(msg, (int)strlen(msg), useTLS);
    }

    bool readHandshake(bool useTLS)
    {
        auto start = std::chrono::steady_clock::now();
        while (true)
        {
            std::string soFar(readBuf.begin(), readBuf.end());
            size_t end = soFar.find("\r\n\r\n");
            if (end != std::string::npos)
                return true;

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= kHandshakeTimeoutMs)
                return false;
            int waitMs = kHandshakeTimeoutMs - (int)elapsed;
            int ready = s.waitReadable(waitMs);
            if (ready <= 0)
                return false;
            if (readBuf.size() >= kMaxHandshakeBytes)
                return false;
            int n = pullBytes(useTLS);
            if (n < 0)
                return false;
        }
    }

    std::string headerValue(const std::vector<std::string>& lines, const char* key)
    {
        std::string want = asciiLower(key);
        for (size_t i = 0; i < lines.size(); ++i)
        {
            std::string line = lines[i];
            std::string lower = asciiLower(line);
            if (lower.compare(0, want.size(), want) == 0)
                return trimWs(line.substr(want.size()));
        }
        return "";
    }

    bool acceptSubprotocol(const std::string& offered, std::string& chosen)
    {
        if (subprotocols.empty())
            return true;
        if (offered.empty())
        {
            chosen.clear();
            return true;
        }
        size_t pos = 0;
        while (pos < offered.size())
        {
            size_t comma = offered.find(',', pos);
            if (comma == std::string::npos)
                comma = offered.size();
            std::string token = trimWs(offered.substr(pos, comma - pos));
            for (size_t i = 0; i < subprotocols.size(); ++i)
            {
                if (token == subprotocols[i])
                {
                    chosen = token;
                    return true;
                }
            }
            pos = comma + 1;
        }
        return false;
    }

    bool initDeflate()
    {
        if (std::string(zlibVersion()) != std::string(ZLIB_VERSION))
        {
            std::cerr << "Zlib version mismatch" << std::endl;
            return false;
        }

        z_stream* comp = (z_stream*)malloc(sizeof(z_stream));
        z_stream* decomp = (z_stream*)malloc(sizeof(z_stream));
        if (!comp || !decomp)
        {
            free(comp);
            free(decomp);
            return false;
        }
        memset(comp, 0, sizeof(z_stream));
        memset(decomp, 0, sizeof(z_stream));

        int res = deflateInit2(comp, compressionLevel, Z_DEFLATED, -compressorBits, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
        if (res != Z_OK)
        {
            std::cerr << "error while initing zlib compressor: " << res << std::endl;
            free(comp);
            free(decomp);
            return false;
        }
        res = inflateInit2(decomp, -deCompressorBits);
        if (res != Z_OK)
        {
            std::cerr << "error while initing zlib decompressor: " << res << std::endl;
            deflateEnd(comp);
            free(comp);
            free(decomp);
            return false;
        }
        compressor.reset(comp);
        deCompressor.reset(decomp);
        return true;
    }

public:
    websocketConnection(class socket&& ss)
    {
        s = std::move(ss);
    }

    websocketConnection(const websocketConnection&) = delete;
    websocketConnection& operator=(const websocketConnection&) = delete;

    websocketConnection(websocketConnection&& other) noexcept
        : s(std::move(other.s))
        , tlsSession(std::move(other.tlsSession))
        , useTlsFlag(other.useTlsFlag)
        , readBuf(std::move(other.readBuf))
        , readPos(other.readPos)
        , pendingOut(std::move(other.pendingOut))
        , assembling(other.assembling)
        , assembleType(other.assembleType)
        , assembleCompressed(other.assembleCompressed)
        , assembleBuf(std::move(other.assembleBuf))
        , enableDeflate(other.enableDeflate)
        , compressorStream(other.compressorStream)
        , deCompressorStream(other.deCompressorStream)
        , compressorBits(other.compressorBits)
        , deCompressorBits(other.deCompressorBits)
        , compressor(std::move(other.compressor))
        , deCompressor(std::move(other.deCompressor))
        , compressionBuf(std::move(other.compressionBuf))
        , deCompressionBuf(std::move(other.deCompressionBuf))
        , url(std::move(other.url))
        , host(std::move(other.host))
        , origin(std::move(other.origin))
        , subprotocols(std::move(other.subprotocols))
        , maxFramePayload(other.maxFramePayload)
        , maxMessageBytes(other.maxMessageBytes)
        , closeFrameSent(other.closeFrameSent)
        , localClose(other.localClose)
        , sawPeerClose(other.sawPeerClose)
        , closeDeadline(other.closeDeadline)
        , lastActivity(other.lastActivity)
        , pingSent(other.pingSent)
        , awaitingPong(other.awaitingPong)
    {
        other.readPos = 0;
        other.enableDeflate = false;
        other.assembling = false;
        other.closeFrameSent = false;
        other.localClose = false;
    }

    websocketConnection& operator=(websocketConnection&& other) noexcept
    {
        if (this != &other)
        {
            close(useTlsFlag, false);
            s = std::move(other.s);
            tlsSession = std::move(other.tlsSession);
            useTlsFlag = other.useTlsFlag;
            readBuf = std::move(other.readBuf);
            readPos = other.readPos;
            pendingOut = std::move(other.pendingOut);
            assembling = other.assembling;
            assembleType = other.assembleType;
            assembleCompressed = other.assembleCompressed;
            assembleBuf = std::move(other.assembleBuf);
            enableDeflate = other.enableDeflate;
            compressorStream = other.compressorStream;
            deCompressorStream = other.deCompressorStream;
            compressorBits = other.compressorBits;
            deCompressorBits = other.deCompressorBits;
            compressor = std::move(other.compressor);
            deCompressor = std::move(other.deCompressor);
            compressionBuf = std::move(other.compressionBuf);
            deCompressionBuf = std::move(other.deCompressionBuf);
            url = std::move(other.url);
            host = std::move(other.host);
            origin = std::move(other.origin);
            subprotocols = std::move(other.subprotocols);
            maxFramePayload = other.maxFramePayload;
            maxMessageBytes = other.maxMessageBytes;
            closeFrameSent = other.closeFrameSent;
            localClose = other.localClose;
            sawPeerClose = other.sawPeerClose;
            closeDeadline = other.closeDeadline;
            lastActivity = other.lastActivity;
            pingSent = other.pingSent;
            awaitingPong = other.awaitingPong;
            other.readPos = 0;
            other.enableDeflate = false;
            other.closeFrameSent = false;
            other.localClose = false;
        }
        return *this;
    }

    void setLimits(uint32_t framePayload, uint32_t messageBytes)
    {
        if (framePayload > 0)
            maxFramePayload = framePayload;
        if (messageBytes > 0)
            maxMessageBytes = messageBytes;
    }

    void setSubprotocols(std::vector<std::string> protocols)
    {
        subprotocols = std::move(protocols);
    }

    // Read the socket once when readSocket is set, then parse.
    // >0 application message, 0 need more, <0 connection finished.
    int pump(websocketMessage& m, bool useTLS, bool readSocket)
    {
        if (!s.isValid())
            return localClose ? kCloseQuiet : socket::kPeerClosed;
        if (sawPeerClose)
            return localClose ? kCloseQuiet : -3;

        if (readSocket)
        {
            int n = pullBytes(useTLS);
            if (n < 0 && buffered() < 2)
                return n;
        }

        int parsed = parseOne(m, useTLS);
        return parsed;
    }

    int sendWebsocketMessage(const websocketMessage& m, bool useTLS)
    {
        if (!s.isValid())
            return socket::kPeerClosed;

        const char* buf = m.buf.data();
        size_t bufSize = m.buf.size();
        bool compressed = false;
        bool control = m.type == FRAME_CLOSE || m.type == FRAME_PING || m.type == FRAME_PONG;

        if (!control && enableDeflate && buf && bufSize >= minBufferSizeForCompression && m.wantCompression && compressor)
        {
            if (!compressPayload(buf, bufSize, buf, bufSize))
                return fail(kCloseProtocol, useTLS);
            compressed = true;
        }

        if (control && bufSize > 125)
            return fail(kCloseProtocol, useTLS);

        size_t offset = 0;
        bool first = true;
        if (bufSize == 0)
        {
            writeFrame(pendingOut, true, false, (uint8_t)m.type, nullptr, 0);
            return flushPendingSend(useTLS);
        }

        while (offset < bufSize)
        {
            size_t chunk = bufSize - offset;
            bool fin = true;
            if (!control && chunk > maxFramePayload)
            {
                chunk = maxFramePayload;
                fin = false;
            }
            uint8_t opcode = first ? (uint8_t)m.type : (uint8_t)FRAME_CONTINUATION;
            bool rsv1 = compressed && first;
            writeFrame(pendingOut, fin, rsv1, opcode, buf + offset, chunk);
            offset += chunk;
            first = false;
            if (control)
                break;
        }
        return flushPendingSend(useTLS);
    }

    int flushSend(bool useTLS)
    {
        return flushPendingSend(useTLS);
    }

    bool hasPendingSend() const
    {
        return !pendingOut.empty();
    }

    bool hasBufferedInput() const
    {
        return buffered() > 0;
    }

    int serviceKeepalive(bool useTLS, std::chrono::steady_clock::time_point now, int intervalMs)
    {
        if (intervalMs <= 0 || !s.isValid() || localClose || closeFrameSent)
            return 0;
        if (awaitingPong)
        {
            if (now - pingSent >= std::chrono::milliseconds(intervalMs))
                return fail(kCloseGoingAway, useTLS);
            return 0;
        }
        if (now - lastActivity >= std::chrono::milliseconds(intervalMs))
        {
            websocketMessage ping;
            ping.type = FRAME_PING;
            ping.wantCompression = false;
            awaitingPong = true;
            pingSent = now;
            int rc = sendWebsocketMessage(ping, useTLS);
            if (rc < 0 && rc != socket::kWouldBlock)
                return rc;
            return rc;
        }
        return 0;
    }

    bool closeTimedOut(std::chrono::steady_clock::time_point now) const
    {
        return localClose && !sawPeerClose && now >= closeDeadline;
    }

    // Sends a normal close and keeps the socket until the peer replies or the timeout.
    // Returns kCloseQuiet when the caller should drop the socket immediately.
    int beginLocalClose(bool useTLS, bool clean)
    {
        if (localClose)
            return sawPeerClose ? kCloseQuiet : 0;
        localClose = true;
        closeDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCloseHandshakeTimeoutMs);
        if (!clean)
        {
            closeFrameSent = true;
            return kCloseQuiet;
        }
        int rc = sendCloseFrame(kCloseNormal, useTLS);
        if (rc < 0 && rc != socket::kWouldBlock)
            return kCloseQuiet;
        return 0;
    }

    std::string getURL() const { return url; }
    std::string getHost() const { return host; }
    std::string getOrigin() const { return origin; }

    bool isOpen()
    {
        return s.isValid();
    }

    void addToWaitSet(EventWait& waitSet, uint32_t id)
    {
        waitSet.add(s, id);
    }

    void noteWriteInterest(EventWait& waitSet, uint32_t id, bool wantWrite)
    {
        waitSet.modify(id, true, wantWrite);
    }

    bool handshake(bool useTLS, bool allowDeflate = true)
    {
        useTlsFlag = useTLS;
        if (useTLS)
        {
            if (!tlsSession.handshake(s))
                return false;
        }

        std::cout << "Receiving websocket http headers..." << std::endl;
        if (!readHandshake(useTLS))
        {
            std::cerr << "error while receiving websocket handshake" << std::endl;
            sendHttp400(useTLS);
            return false;
        }

        std::string raw(readBuf.begin(), readBuf.end());
        size_t headerEnd = raw.find("\r\n\r\n");
        // Include the trailing CRLF so splitHeader keeps the last header line.
        // Bytes after the blank line stay in readBuf and are websocket frames.
        std::string head = raw.substr(0, headerEnd + 2);
        std::string rest = raw.substr(headerEnd + 4);
        readBuf.assign(rest.begin(), rest.end());
        readPos = 0;

        std::vector<std::string> headerLines;
        splitHeader(head, headerLines);

        if (headerLines.empty())
        {
            sendHttp400(useTLS);
            return false;
        }

        // Example:
        /*
        GET /?t=tokenstring HTTP/1.1
        Host: 192.168.1.55:50005
        Connection: Upgrade
        Pragma: no-cache
        Cache-Control: no-cache
        User-Agent: Mozilla/5.0
        Upgrade: websocket
        Origin: https://192.168.1.55
        Sec-WebSocket-Version: 13
        Accept-Encoding: gzip, deflate, br, zstd
        Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
        Sec-WebSocket-Key: el6Up+NwfiF2YralM2EDlg==
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
        */

        std::string request = headerLines[0];
        if (request.compare(0, 4, "GET ") != 0 || request.size() < 14 ||
            request.compare(request.size() - 8, 8, "HTTP/1.1") != 0)
        {
            std::cerr << "Websocket handshake is not HTTP/1.1 GET" << std::endl;
            sendHttp400(useTLS);
            return false;
        }
        size_t pathStart = 4;
        size_t pathEnd = request.find(' ', pathStart);
        if (pathEnd == std::string::npos)
        {
            sendHttp400(useTLS);
            return false;
        }
        url = request.substr(pathStart, pathEnd - pathStart);

        host = headerValue(headerLines, "host: ");
        origin = headerValue(headerLines, "origin: ");
        std::string upgrade = headerValue(headerLines, "upgrade: ");
        std::string connection = headerValue(headerLines, "connection: ");
        std::string wsVersion = headerValue(headerLines, "sec-websocket-version: ");
        std::string wsExtensions = headerValue(headerLines, "sec-websocket-extensions: ");
        std::string webSocketKey = headerValue(headerLines, "sec-websocket-key: ");
        std::string offeredProto = headerValue(headerLines, "sec-websocket-protocol: ");

        if (!headerTokenHas(upgrade, "websocket") || !headerTokenHas(connection, "upgrade"))
        {
            std::cerr << "Websocket handshake missing Upgrade" << std::endl;
            sendHttp400(useTLS);
            return false;
        }
        if (wsVersion != "13")
        {
            std::cerr << "WS version not 13, abort handshake" << std::endl;
            sendHttp400(useTLS);
            return false;
        }
        // RFC 6455 section 4.2.1: Sec-WebSocket-Key decodes to 16 bytes.
        // base64_decode is libwebutil; decodeBase64Url asserts, which would kill the handshake thread.
        std::string normalisedKey = normalizeBase64(trimWs(webSocketKey));
        char keyRaw[24];
        size_t keyLen = sizeof(keyRaw);
        int keyOk = base64_decode(normalisedKey.data(), normalisedKey.size(), keyRaw, &keyLen, 0);
        if (keyOk != 1 || keyLen != 16)
        {
            std::cerr << "Couldn't find WS key, abort handshake" << std::endl;
            sendHttp400(useTLS);
            return false;
        }

        std::string chosenProto;
        if (!acceptSubprotocol(offeredProto, chosenProto))
        {
            std::cerr << "Websocket subprotocol rejected" << std::endl;
            sendHttp400(useTLS);
            return false;
        }

        bool offerDeflate = false;
        bool includeClientBits = false;
        bool includeServerBits = false;
        if (allowDeflate)
        {
            size_t extPos = 0;
            std::string ext = wsExtensions;
            while (extPos < ext.size())
            {
                size_t comma = ext.find(',', extPos);
                if (comma == std::string::npos)
                    comma = ext.size();
                std::string offer = trimWs(ext.substr(extPos, comma - extPos));
                extPos = comma + 1;
                std::string offerLower = asciiLower(offer);
                if (offerLower.compare(0, 18, "permessage-deflate") != 0)
                    continue;
                if (offerLower.size() > 18 && offerLower[18] != ';' && offerLower[18] != ' ' && offerLower[18] != '\t')
                    continue;

                offerDeflate = true;
                compressorStream = true;
                deCompressorStream = true;
                compressorBits = 15;
                deCompressorBits = 15;
                includeClientBits = false;
                includeServerBits = false;

                size_t semi = 0;
                while (semi < offer.size())
                {
                    size_t next = offer.find(';', semi);
                    if (next == std::string::npos)
                        next = offer.size();
                    std::string param = trimWs(offer.substr(semi, next - semi));
                    semi = next + 1;
                    std::string plow = asciiLower(param);
                    if (plow == "permessage-deflate")
                        continue;
                    auto eq = plow.find('=');
                    std::string name = eq == std::string::npos ? plow : plow.substr(0, eq);
                    std::string value = eq == std::string::npos ? "" : trimWs(param.substr(eq + 1));
                    if (name == "client_no_context_takeover")
                        deCompressorStream = false;
                    else if (name == "server_no_context_takeover")
                        compressorStream = false;
                    else if (name == "client_max_window_bits")
                    {
                        includeClientBits = true;
                        if (!parseWindowBits(value, deCompressorBits))
                        {
                            sendHttp400(useTLS);
                            return false;
                        }
                    }
                    else if (name == "server_max_window_bits")
                    {
                        includeServerBits = true;
                        if (!parseWindowBits(value, compressorBits))
                        {
                            sendHttp400(useTLS);
                            return false;
                        }
                    }
                }
                break;
            }
        }

        if (offerDeflate)
        {
            enableDeflate = true;
            if (!initDeflate())
            {
                enableDeflate = false;
                sendHttp400(useTLS);
                return false;
            }
        }

        std::string responseKey = getHandshakeResponseKey(webSocketKey + magicString);
        std::string response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + responseKey + "\r\n";
        if (!chosenProto.empty())
            response += "Sec-WebSocket-Protocol: " + chosenProto + "\r\n";
        if (enableDeflate)
        {
            response += "Sec-WebSocket-Extensions: permessage-deflate";
            if (includeClientBits)
                response += "; client_max_window_bits=" + std::to_string(deCompressorBits);
            if (includeServerBits)
                response += "; server_max_window_bits=" + std::to_string(compressorBits);
            if (!deCompressorStream)
                response += "; client_no_context_takeover";
            if (!compressorStream)
                response += "; server_no_context_takeover";
            response += "\r\n";
        }
        response += "\r\n";

        std::cout << "Sending websocket handshake response..." << std::endl;
        if (!sendHttp(response, useTLS))
        {
            std::cerr << "error while sending websocket handshake response" << std::endl;
            return false;
        }
        return true;
    }

    void close(bool useTLS, bool clean = true)
    {
        std::cout << "WebsocketConnection close" << std::endl;
        if (!s.isValid())
        {
            compressor.reset();
            deCompressor.reset();
            enableDeflate = false;
            return;
        }

        if (clean && !closeFrameSent)
            sendCloseFrame(kCloseNormal, useTLS);

        if (useTLS)
            tlsSession.close(clean);

        compressor.reset();
        deCompressor.reset();
        enableDeflate = false;
        s.close(clean);
    }
};

const std::string websocketConnection::magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
