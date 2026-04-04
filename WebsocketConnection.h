#pragma once

#include "libsocket/Socket.h"
#include "WebsocketMessage.h"
#include "TLSutil.h"

#ifdef Z_SOLO
#error "Z_SOLO defined, but we use standard malloc"
#endif
#include "zlib/zlib.h"

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <chrono>

static void splitHeader(const std::string& header, std::vector<std::string>& splitHeader)
{
    std::string copy = header;
    std::string delimiter = "\r\n";
    size_t pos = 0;
    while ((pos = copy.find(delimiter)) != std::string::npos)
    {
        std::string line = copy.substr(0, pos);
        splitHeader.push_back(line);
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
    CryptBinaryToStringA(hashBytes.data(), hashBytesSize, CRYPT_STRING_BASE64, hashStrBuf.data(), &hashStrBufLen);

    CryptReleaseContext(cryptoProvider, 0);
    CryptDestroyHash(hashProvider);

    return std::string(hashStrBuf.begin(), hashStrBuf.end());
#else
    char* hashPtr = (char*)SHA1((const unsigned char*)webSocketKey.data(), webSocketKey.length(), nullptr);
    std::vector<char> hashBuf(20);
    memcpy(hashBuf.data(), hashPtr, 20);

    std::vector<char> hashStrBuf;
    {
        BIO *bmem, *b64;
        BUF_MEM *bptr;

        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, hashBuf.data(), hashBuf.size());
        BIO_flush(b64);
        BIO_get_mem_ptr(b64, &bptr);

        hashStrBuf.resize(bptr->length);
        memcpy(hashStrBuf.data(), bptr->data, bptr->length);

        BIO_free_all(b64);
    }
    return std::string(hashStrBuf.begin(), hashStrBuf.end() - 1);
#endif
}

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

class websocketConnection
{
private:

	class socket s;
    TLSsession tlsSession;

    int recv(char* buf, int len, bool useTLS, bool singleRecv = false)
    {
        if (useTLS)
        {
            return tlsSession.receiveMessage(buf, len, singleRecv);
        }
        else
        {
            return s.receive(buf, len, singleRecv);
        }
    }

    int send(const char* buf, int len, bool useTLS)
    {
        if (useTLS)
        {
            return tlsSession.sendMessage(buf, len);
        }
        else
        {
            return s.send(buf, len);
        }
    }

    bool enableDeflate = false;
    bool compressorStream = true;
    bool deCompressorStream = true;
    const int32_t compressorBits = 15;
    const int32_t deCompressorBits = 15;
    //buffer must be at least N bytes to use compression
    //below that deflate might compress it to a larger size
    //or just slightly smaller size and then it's not worth it
    const uint32_t minBufferSizeForCompression = 256;
    z_stream* compressor = nullptr;
    z_stream* deCompressor = nullptr;
    const int32_t compressionLevel = Z_BEST_COMPRESSION; //max
    std::vector<char> compressionBuf;
    std::vector<char> deCompressionBuf;

    std::string url;

    const static std::string magicString;
public:

    int receiveWebsocketMessage(websocketMessage& m, bool useTLS)
    {
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
        /**/

        bool debugPrint = false;

        uint32_t startSize = m.buf.size();

        m.type = (frameType)0xff;

        bool firstFrame = true;
        bool isCompressed = false;

        if (debugPrint) 
        {
            std::cout << "Receiving websocket message, startsize: " << startSize << std::endl;
        }

        //Websocket frames may come in multiple messages
        //Indicated by the fin bit whether it's the last one or not
        bool fin = false;
        while (!fin)
        {
            std::vector<char> receiveBuf;

            //read just the header, then we can decide if we need more
            receiveBuf.resize(sizeof(websocketHeader));
 
            int ret = recv(receiveBuf.data(), receiveBuf.size(), useTLS);

            //other side closed the connection or some other error
            if (ret < 0)
            {
                return ret;
            }

            uint32_t payloadByteOffset = 0;

            websocketHeader h = {};
            derefRawData(getRawData<websocketHeader>(receiveBuf, payloadByteOffset), h);

            fin = h.fin;
            uint64_t payloadLen = h.payloadLen;

            if (debugPrint) 
            {
                std::cout << "fin: " << h.fin << std::endl;
                std::cout << "RSV123: " << h.rsv1 << " " << h.rsv2 << " " << h.rsv3 << std::endl;
                std::cout << "opcode: " << uint32_t(h.opcode) << std::endl;
                std::cout << "masked: " << h.masked << std::endl;
            }

            if(enableDeflate)
            {
                //with deflate rsv1 indicates if the frame is compressed
                if (h.rsv2 || h.rsv3)
                {
                    std::cerr << "Websocket header rsv2,3 must be zero unless an extension is negotiated" << std::endl;
                    std::cerr << h.rsv2 << " " << h.rsv3 << std::endl;
                    close(useTLS);
                    return -1;
                }

                if(firstFrame && h.rsv1)
                {
                    isCompressed = true;
                }
            }
            else
            {
                if (h.rsv1 || h.rsv2 || h.rsv3)
                {
                    std::cerr << "Websocket header rsv1,2,3 must be zero unless an extension is negotiated" << std::endl;
                    std::cerr << h.rsv1 << " " << h.rsv2 << " " << h.rsv3 << std::endl;
                    close(useTLS);
                    return -1;
                }
            }

            //opcode must be valid
            if (h.opcode > 0xf) {
                std::cerr << "Websocket header opcode must be valid " << h.opcode << std::endl;
                close(useTLS);
                return -1;
            }

            //client to server comms must be masked
            if (!h.masked) {
                std::cerr << "Websocket client to server comms must be masked " << h.masked << std::endl;
                close(useTLS);
                return -1;
            }

            if (payloadLen == 126)
            {
                receiveBuf.resize(receiveBuf.size() + sizeof(uint16_t));

                ret = recv(receiveBuf.data() + payloadByteOffset, sizeof(uint16_t), useTLS);

                if (ret < 0)
                {
                    return ret;
                }
                
                uint16_t payloadLen16 = {};
                derefRawData(getRawData<uint16_t>(receiveBuf, payloadByteOffset), payloadLen16);

                payloadLen = swapEndianness(payloadLen16);
            }
            else if (payloadLen == 127)
            {
                receiveBuf.resize(receiveBuf.size() + sizeof(uint64_t));

                ret = recv(receiveBuf.data() + payloadByteOffset, sizeof(uint64_t), useTLS);

                if (ret < 0)
                {
                    return ret;
                }

                payloadLen = {};
                derefRawData(getRawData<uint64_t>(receiveBuf, payloadByteOffset), payloadLen);

                payloadLen = swapEndianness(payloadLen);
            }

            if (debugPrint) 
            {
                std::cout << "payload len bytes: " << payloadLen << std::endl;
            }

            //add masking key
            receiveBuf.resize(receiveBuf.size() + payloadLen + sizeof(uint32_t));

            ret = recv(receiveBuf.data() + payloadByteOffset, payloadLen  + sizeof(uint32_t), useTLS);

            if (ret < 0)
            {
                return ret;
            }

            //Handle fragmented messages properly
            //https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
            if(h.opcode == FRAME_CLOSE)
            {
                if(debugPrint)
                {
                    std::cout << "Got websocketMessage with close frame" << std::endl;
                }
                close(useTLS);
                return -2;
            }
            else if(h.opcode == FRAME_PING)
            {
                websocketMessage mm;
                mm.type = FRAME_PONG;
                sendWebsocketMessage(mm, useTLS);
                continue;
            }
            else if(h.opcode == FRAME_PONG)
            {
                continue;
            }

            if ((m.type == 0xff && fin && h.opcode != 0) //unfragmented message
                || (m.type == 0xff && !fin && h.opcode != 0)) //fragmented message first frame
            {
                m.type = (frameType)h.opcode;
            }
            else if (m.type != 0xff && fin)
            {
                //fragmented message last frame must have this
                if (h.opcode != 0)
                {
                    std::cerr << "Got a fragmented websocket last frame with invalid opcode " << h.opcode << std::endl;
                    close(useTLS);
                    return -1;
                }
            }
            else
            {
                //fragmented frames that are not the first or last frame need to have these
                if (!(!fin && h.opcode == 0))
                {
                    std::cerr << "Got a fragmented websocket mid frame with invalid opcode " << h.opcode << std::endl;
                    close(useTLS);
                    return -1;
                }
            }

            uint8_t mask[4];
            for (int c = 0; c < 4; ++c)
            {
                mask[c] = {};
                derefRawData(getRawData<uint8_t>(receiveBuf, payloadByteOffset), mask[c]);
            }

            if (debugPrint) 
            {
                std::cout << "masking key: " << uint32_t(mask[0]) << " " << uint32_t(mask[1]) << " " << uint32_t(mask[2]) << " " << uint32_t(mask[3]) << std::endl;
            }

            const char* encodedData = getRawData<char>(receiveBuf, payloadByteOffset, payloadLen);

            if (encodedData)
            {
                //decode xor encryption
                std::vector<char> decodedData(payloadLen);
                for (uint64_t c = 0; c < payloadLen; ++c)
                {
                    decodedData[c] = encodedData[c] ^ mask[c % 4];
                }

                m.buf.insert(std::end(m.buf), decodedData.begin(), decodedData.end());
            }
            else
            {
                if (debugPrint)
                {
                    std::cout << "Encoded data null" << std::endl;
                }

                return -1;
            }

            if(firstFrame)
            {
                firstFrame = false;
            }
        }

        if(isCompressed && (m.buf.size() - startSize) > 0)
        {
            if(!deCompressor)
            {
                std::cerr << "decompressor not inited" << std::endl;
                return -1;
            }

            //decompress message
            bool hasTail = false;
                //(m.buf.size() - startSize) >= 4 &&
                //m.buf[m.buf.size() - startSize - 4] == 0x00 &&
                //m.buf[m.buf.size() - startSize - 3] == 0x00 &&
                //m.buf[m.buf.size() - startSize - 2] == 0xff &&
                //m.buf[m.buf.size() - startSize - 1] == 0xff;

            if(debugPrint)
            {
                std::cout << "Has tail: " << hasTail << std::endl;
            }

            if(!hasTail)
            {
                std::vector<char> appendix = {0x00, 0x00, 0xff, 0xff};
                m.buf.insert(std::end(m.buf), appendix.begin(), appendix.end());
            }

            if(debugPrint)
            {
                for(uint32_t c = startSize; c < (m.buf.size() - startSize); ++c)
                {
                    printf("0x%02X ", m.buf[c]);
                    //printf("%c", m.buf[c]);
                }
                printf("\n");
            }

            //reasonable starting decompression buf size
            deCompressionBuf.resize((m.buf.size() - startSize) * 3 + 1024);

            uint32_t decompressedSize = 0;

            deCompressor->next_in = (unsigned char*)m.buf.data() + startSize;
            deCompressor->avail_in = m.buf.size() - startSize;
            deCompressor->next_out = (unsigned char*)deCompressionBuf.data();
            deCompressor->avail_out = deCompressionBuf.size();
            
            while(true)
            {
                if(debugPrint)
                {
                    std::cout << "before: " << std::endl;
                    std::cout << "next out: " << (void*)deCompressor->next_out << std::endl;
                    std::cout << "avail_out: " << deCompressor->avail_out << std::endl;
                    std::cout << "next_in: " << (void*)deCompressor->next_in << std::endl;
                    std::cout << "avail_in: " << deCompressor->avail_in << std::endl;
                }

                uint32_t before = deCompressor->avail_out;

                int res = inflate(deCompressor, Z_SYNC_FLUSH);

                decompressedSize += before - deCompressor->avail_out;

                if(debugPrint)
                {
                    std::cout << "after: " << res << std::endl;
                    std::cout << "next out: " << (void*)deCompressor->next_out << std::endl;
                    std::cout << "avail_out: " << deCompressor->avail_out << std::endl;
                    std::cout << "next_in: " << (void*)deCompressor->next_in << std::endl;
                    std::cout << "avail_in: " << deCompressor->avail_in << std::endl;
                }

                if(res == Z_BUF_ERROR || (res == Z_OK && deCompressor->avail_out == 0))
                {
                    uint32_t oldSize = deCompressionBuf.size();
                    //double decompression buffer size and try again
                    deCompressionBuf.resize(deCompressionBuf.size() * 2);

                    deCompressor->next_out = (Bytef*)deCompressionBuf.data() + oldSize;
                    deCompressor->avail_out = deCompressionBuf.size() - oldSize;
                }
                else if((res == Z_OK || res == Z_STREAM_END) && deCompressor->avail_in == 0)
                {
                    //status code okay and all input bytes consumed
                    break;
                }
                else
                {
                    std::cerr << "Error while running zlib decompression: " << res << std::endl;

                    return -1;
                }
            }

            if(debugPrint)
            {
                std::cout << "Decompressed buf: " << decompressedSize << std::endl;
                //std::cout << std::string(deCompressionBuf.begin(), deCompressionBuf.end()) << std::endl;
            }

            //on success copy the decompressed data to the output message
            m.buf.resize(startSize + decompressedSize);
            memcpy(m.buf.data() + startSize, deCompressionBuf.data(), decompressedSize);

            if(!deCompressorStream)
            {
                if(inflateEnd(deCompressor) != Z_OK)
                {
                    std::cerr << "failed ending decompressor" << std::endl;
                    return -1;
                }

                if(inflateInit2(deCompressor, -deCompressorBits) != Z_OK)
                {
                    std::cerr << "failed re-initing decompressor" << std::endl;
                    return -1;
                }
            }
        }

        return m.buf.size() - startSize;
    }

    int sendWebsocketMessage(const websocketMessage& m, bool useTLS)
    {
        bool debugPrint = false;

        if (debugPrint) 
        {
            std::cout << "Sending websocket message" << std::endl;
            //std::cout << std::string(m.buf.begin(), m.buf.end()) << std::endl;
        }

        std::vector<char> outBuf;

        websocketHeader h = {};
        h.opcode = m.type; //frame type
        h.masked = false; //server must send unmasked
        h.fin = true; //we'll just send one frame to keep it simple, it can be huge anyways

        const char* buf = m.buf.data();
        size_t bufSize = m.buf.size();

        if(enableDeflate && buf && bufSize && bufSize >= minBufferSizeForCompression)
        {
            //flip rsv1 bit to indicate compressed frame
            h.rsv1 = 1;

            compressionBuf.resize(compressBound(m.buf.size()));

            compressor->next_out = (unsigned char*)compressionBuf.data();
            compressor->avail_out = compressionBuf.size();
            compressor->next_in = (unsigned char*)m.buf.data();
            compressor->avail_in = m.buf.size();

            if(debugPrint)
            {
                std::cout << "before: " << std::endl;
                std::cout << "next out: " << (void*)compressor->next_out << std::endl;
                std::cout << "avail_out: " << compressor->avail_out << std::endl;
                std::cout << "next_in: " << (void*)compressor->next_in << std::endl;
                std::cout << "avail_in: " << compressor->avail_in << std::endl;
            }

            uint32_t before = compressor->avail_out;

            int flushMode = compressorStream ? Z_FULL_FLUSH : Z_SYNC_FLUSH;

            int res = deflate(compressor, flushMode);

            uint32_t compressedSize = before - compressor->avail_out;

            if(debugPrint)
            {
                std::cout << "after: " << res << std::endl;
                std::cout << "next out: " << (void*)compressor->next_out << std::endl;
                std::cout << "avail_out: " << compressor->avail_out << std::endl;
                std::cout << "next_in: " << (void*)compressor->next_in << std::endl;
                std::cout << "avail_in: " << compressor->avail_in << std::endl;
            }

            if(res < 0)
            {
                std::cerr << "websocket message compression res: " << res << std::endl;
                return -1;
            }

            if(res == Z_OK && compressor->avail_out == 0)
            {
                std::cerr << "compressor ran out of space" << std::endl;
                return -1;
            }

            if(compressor->avail_in > 0)
            {
                std::cerr << "couldn't deflate all input in one go " << compressor->avail_in << std::endl;
                return -1;
            }

            if(debugPrint)
            {
                std::cout << "compressed size: " << compressedSize << std::endl;
                std::cout << "before tail stripping" << std::endl;
                for(uint32_t c = 0; c < compressedSize; ++c)
                {
                    printf("0x%02X ", compressionBuf[c]);
                    //printf("%c", m.buf[c]);
                }
                printf("\n");
            }

            bool hasTail = true;
            //compressionBuf.size() >= 4 &&
            //compressionBuf[compressionBuf.size() - 4] == 0x00 &&
            //compressionBuf[compressionBuf.size() - 3] == 0x00 &&
            //compressionBuf[compressionBuf.size() - 2] == 0xff &&
            //compressionBuf[compressionBuf.size() - 1] == 0xff;

            buf = compressionBuf.data();
            bufSize = compressedSize - (hasTail ? 4 : 0); //account for flush marker

            if(!compressorStream)
            {
                if(deflateReset(compressor) != Z_OK)
                {
                    std::cerr << "failed resetting compressor state" << std::endl;
                    return -1;
                }
            }
        }

        uint16_t maxFourBytesPayloadSize = 0;
        maxFourBytesPayloadSize = ~maxFourBytesPayloadSize;

        if (bufSize < 126)
        {
            h.payloadLen = bufSize;

            outBuf.reserve(sizeof(h) + bufSize);

            setRawData(outBuf, &h);
            if (buf && bufSize)
            {
                setRawData(outBuf, buf, bufSize);
            }
        }
        else if (bufSize < size_t(maxFourBytesPayloadSize))
        {
            h.payloadLen = 126;
            uint16_t extendedPayloadLen = bufSize;
            uint16_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

            outBuf.reserve(sizeof(h) + sizeof(uint16_t) + bufSize);

            setRawData(outBuf, &h);
            setRawData(outBuf, &extendedPayloadLenBE);
            if (buf && bufSize)
            {
                setRawData(outBuf, buf, bufSize);
            }
        }
        else
        {
            assert(bufSize < (~0ull >> 1));

            h.payloadLen = 127;
            uint64_t extendedPayloadLen = bufSize;
            uint64_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

            outBuf.reserve(sizeof(h) + sizeof(uint64_t) + bufSize);

            setRawData(outBuf, &h);
            setRawData(outBuf, &extendedPayloadLenBE);
            if (buf && bufSize)
            {
                setRawData(outBuf, buf, bufSize);
            }
        }

        if (debugPrint) 
        {
            std::cout << "fin: " << h.fin << std::endl;
            std::cout << "RSV123: " << h.rsv1 << " " << h.rsv2 << " " << h.rsv3 << std::endl;
            std::cout << "opcode: " << uint32_t(h.opcode) << std::endl;
            std::cout << "masked: " << h.masked << std::endl;
            std::cout << "payload len bytes: " << bufSize << std::endl;
        }

        return send(outBuf.data(), outBuf.size(), useTLS);
    }

    std::string getURL() const
    {
        return url;
    }

    bool operator==(const websocketConnection& c) const
    {
        return s == c.s;
    }

    bool handshake(bool useTLS)
    {
        bool debugPrint = false;

        if (useTLS) 
        {
            if (!tlsSession.handshake(s))
            {
                return false;
            }
        }

        std::cout << "Receiving websocket http headers..." << std::endl;

        std::vector<std::string> headerLines;
        {
            std::cout << "Check if we got any data..." << std::endl;

            while (!s.receivedAnyBytes())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            std::cout << "Reading data..." << std::endl;

            std::vector<char> receiveBuf;
            receiveBuf.resize(16384);

            int ret = recv(receiveBuf.data(), receiveBuf.size(), useTLS, true);

            if (ret <= 0)
            {
                std::cerr << "error while receiving websocket handshake" << std::endl;
                return false;
            }

            std::cout << "We got " << ret << " bytes" << std::endl;

            splitHeader(receiveBuf.data(), headerLines);
        }

        //extract information from headers
        //Store this info in the connection class
        //Make it retrievable, as for example we would 
        //grab the session token from the url
        // 
        //Host, GET url, origin
        //Make sure websocket-version is 1.3
        //Make sure client supports deflate, 
        //including permessage-deflate extension
        //
        //Example:
        /*
        * 
        GET /?t=tokenstring HTTP/1.1
        Host: 192.168.1.55:50005
        Connection: Upgrade
        Pragma: no-cache
        Cache-Control: no-cache
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
        Upgrade: websocket
        Origin: https://192.168.1.55
        Sec-WebSocket-Version: 13
        Accept-Encoding: gzip, deflate, br, zstd
        Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,hu;q=0.7,ca;q=0.6,es;q=0.5
        Sec-WebSocket-Key: el6Up+NwfiF2YralM2EDlg==
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
        */

        std::string host, origin, userAgent;

        for (auto& line : headerLines)
        {
            //example:
            //GET /?t=tokenstring HTTP/1.1
            std::string str = "GET ";
            size_t pos = line.find(str);
            size_t nextSpacePos = line.find(" ", str.length());
            if (pos != std::string::npos && pos == 0)
            {
                url = line.substr(str.length(),nextSpacePos - str.length());
                break;
            }
        }

        auto extractString = [](std::vector<std::string>& lines, const std::string& key)
        {
            std::string result;
            for (auto& line : lines)
            {
                size_t pos = line.find(key);
                if (pos != std::string::npos && pos == 0)
                {
                    result += line.substr(key.length());
                }
            }

            return result;
        };

        host = extractString(headerLines, "Host: ");
        userAgent = extractString(headerLines, "User-Agent: ");
        origin = extractString(headerLines, "Origin: ");
        std::string acceptEncoding = extractString(headerLines, "Accept-Encoding: ");
        std::string wsVersion = extractString(headerLines, "Sec-WebSocket-Version: ");
        std::string wsExtensions = extractString(headerLines, "Sec-WebSocket-Extensions: ");
        std::string webSocketKey = extractString(headerLines, "Sec-WebSocket-Key: ");

        if (debugPrint)
        {
            std::cout << "URL: " << url << std::endl;
            std::cout << "User agent: " << userAgent << std::endl;
            std::cout << "Origin: " << origin << std::endl;
            std::cout << "Accept encoding: " << acceptEncoding << std::endl;
            std::cout << "WS version: " << wsVersion << std::endl;
            std::cout << "WS extensions: " << wsExtensions << std::endl;
            std::cout << "WS key: " << webSocketKey << std::endl;

            std::cout << std::endl << "Header lines: " << std::endl;
            for (auto& line : headerLines)
            {
                std::cout << line << std::endl;
            }
        }
        
        if(wsExtensions.find("permessage-deflate") != wsExtensions.npos)
        {
            enableDeflate = true;
        }

        if(wsExtensions.find("server_no_context_takeover") != wsExtensions.npos)
        {
            compressorStream = false;
        }

        if(wsExtensions.find("client_no_context_takeover") != wsExtensions.npos)
        {
            deCompressorStream = false;
        }

        auto getVal = [](const std::string& str, const std::string& tofind) -> std::string
        {
            //find token we're looking for
            auto it = str.find(tofind);
            if(it == str.npos) return "";

            //clip it off so we can only have
            // "" -> end of header line
            // "; rest of the header line"
            // "=[val]; rest of header line"
            std::string sub = str.substr(it + tofind.length());

            auto valIt = sub.find(";");

            //if we have a semicolon, we might have a value
            if(valIt != sub.npos)
            {
                //in case we only have the semicolon, don't get the whole string
                return sub.substr(1, valIt > 0 ? valIt - 1 : 0);
            }

            return "";
        };

        bool includeServerBitsInResponse = false;
        if(wsExtensions.find("server_max_window_bits") != wsExtensions.npos)
        {
            includeServerBitsInResponse = true;

            auto valueStr = getVal(wsExtensions, "server_max_window_bits");

            if(!valueStr.empty())
            {
                uint32_t bits = std::stoi(valueStr);

                //libdeflate has a hardcoded 32KB sliding window so bits must be 15
                if(bits < 15) return false;
            }
        }

        bool includeClientBitsInResponse = false;
        if(wsExtensions.find("client_max_window_bits") != wsExtensions.npos)
        {
            includeClientBitsInResponse = true;

            auto valueStr = getVal(wsExtensions, "client_max_window_bits");

            if(!valueStr.empty())
            {
                uint32_t bits = std::stoi(valueStr);

                //libdeflate has a hardcoded 32KB sliding window so bits must be 15
                if(bits < 15) return false;
            }
        }

        if (webSocketKey.empty()) 
        {
            std::cerr << "Couldn't find WS key, abort handshake" << std::endl;
            return false;
        }        

        if (wsVersion.empty() || wsVersion != "13")
        {
            std::cerr << "WS version not 1.3, abort handshake" << std::endl;
            return false;
        }

        //prepare websocket handshake response
        webSocketKey += magicString;

        std::string responseKey = getHandshakeResponseKey(webSocketKey);

        if(debugPrint)
        {
            std::cout << responseKey << std::endl;
        }

        std::string websocketHandshakeResponse =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + responseKey + "\r\n";

        if(enableDeflate)
        {
            websocketHandshakeResponse += "Sec-WebSocket-Extensions: permessage-deflate";
            
            if(includeClientBitsInResponse)
            {
                websocketHandshakeResponse += "; client_max_window_bits=" + std::to_string(deCompressorBits);
            }

            if(includeClientBitsInResponse)
            {
                websocketHandshakeResponse += "; server_max_window_bits=" + std::to_string(compressorBits);
            }

            if(!deCompressorStream)
            {
                websocketHandshakeResponse += "; client_no_context_takeover";
            }

            if(!compressorStream)
            {
                websocketHandshakeResponse += "; server_no_context_takeover";
            }

            websocketHandshakeResponse += "\r\n";
        }

        //must have a close
        websocketHandshakeResponse += "\r\n";

        if (debugPrint) {
            std::cout << websocketHandshakeResponse << std::endl;
        }

        std::cout << "Sending websocket handshake response..." << std::endl;

        int ret = send((const char*)websocketHandshakeResponse.data(), websocketHandshakeResponse.size(), useTLS);
        if (ret < 0)
        {
            std::cerr << "error while sending websocket handshake response" << std::endl;
            return false;
        }

        if(enableDeflate)
        {
            assert(std::string(zlibVersion()) == std::string(ZLIB_VERSION));

            compressor = (z_stream*)malloc(sizeof(z_stream));
            deCompressor = (z_stream*)malloc(sizeof(z_stream));
            memset(compressor, 0, sizeof(z_stream));
            memset(deCompressor, 0, sizeof(z_stream));

            //could use _ex version if custom malloc/free is used
            int res = 0;
            res = deflateInit2(compressor, compressionLevel, Z_DEFLATED, -compressorBits, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

            if(res != Z_OK)
            {
                std::cerr << "error while initing zlib compressor: " << res << std::endl;
                return false;
            }
            
            res = inflateInit2(deCompressor, -deCompressorBits);

            if(res != Z_OK)
            {
                std::cerr << "error while initing zlib decompressor: " << res << std::endl;
                return false;
            }
        }

        //could return false to reject invalid handshakes
        return true;
    }

	websocketConnection(class socket&& ss)
	{
		s = std::move(ss);
	}

    bool receivedAnyBytes()
    {
        //TODO this can assert if we closed the connection
        //make sure we don't try to access the socket if the connection is already closed
        return s.receivedAnyBytes();
    }

    bool isOpen()
    {
        return s.isValid();
    }

	void close(bool useTLS, bool clean = true)
	{
        std::cout << "WebsocketConnection close" << std::endl;

        if (!s.isValid()) return;

        if (clean)
        {
            websocketMessage m;
            m.type = FRAME_CLOSE;
            sendWebsocketMessage(m, useTLS);
        }

        if (useTLS)
        {
            tlsSession.close(clean);
        }

        if(enableDeflate)
        {
            deflateEnd(compressor);
            inflateEnd(deCompressor);

            free(compressor);
            free(deCompressor);
        }
        
        s.close(clean);
	}	
};

const std::string websocketConnection::magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";