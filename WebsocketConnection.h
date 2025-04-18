#pragma once

#include "libsocket/Socket.h"
#include "WebsocketMessage.h"
#include "TLSutil.h"

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
    char* hashPtr = (char*)SHA1((const unsigned char*)webSocketKey.data(), webSocketKey.length(), 0);
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
    return std::string(hashStrBuf.begin(), hashStrBuf.end());
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

        int startSize = m.buf.size();

        m.type = (frameType)0xff;

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

            if (h.rsv1 || h.rsv2 || h.rsv3)
            {
                std::cerr << "Websocket header rsv1,2,3 must be zero unless an extension is negotiated" << std::endl;
                std::cerr << h.rsv1 << " " << h.rsv2 << " " << h.rsv3 << std::endl;
                close(useTLS);
                return -1;
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

            char* encodedData = getRawData<char>(receiveBuf, payloadByteOffset, payloadLen);

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
        }

        return m.buf.size() - startSize;
    }

    int sendWebsocketMessage(const websocketMessage& m, bool useTLS)
    {
        std::vector<char> outBuf;

        websocketHeader h = {};
        h.opcode = m.type; //frame type
        h.masked = false; //server must send unmasked
        h.fin = true; //we'll just send one frame to keep it simple, it can be huge anyways

        uint16_t maxFourBytesPayloadSize = 0;
        maxFourBytesPayloadSize = ~maxFourBytesPayloadSize;

        if (m.buf.size() < 126)
        {
            h.payloadLen = m.buf.size();

            outBuf.reserve(sizeof(h) + m.buf.size());

            setRawData(outBuf, &h);
            if (!m.buf.empty())
            {
                setRawData(outBuf, m.buf.data(), m.buf.size());
            }
        }
        else if (m.buf.size() < size_t(maxFourBytesPayloadSize))
        {
            h.payloadLen = 126;
            uint16_t extendedPayloadLen = m.buf.size();
            uint16_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

            outBuf.reserve(sizeof(h) + sizeof(uint16_t) + m.buf.size());

            setRawData(outBuf, &h);
            setRawData(outBuf, &extendedPayloadLenBE);
            if (!m.buf.empty())
            {
                setRawData(outBuf, m.buf.data(), m.buf.size());
            }
        }
        else
        {
            assert(m.buf.size() < (~0ull >> 1));

            h.payloadLen = 127;
            uint64_t extendedPayloadLen = m.buf.size();
            uint64_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

            outBuf.reserve(sizeof(h) + sizeof(uint64_t) + m.buf.size());

            setRawData(outBuf, &h);
            setRawData(outBuf, &extendedPayloadLenBE);
            if (!m.buf.empty())
            {
                setRawData(outBuf, m.buf.data(), m.buf.size());
            }
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

            receiveBuf.resize(ret);

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
            for (auto& line : lines)
            {
                size_t pos = line.find(key);
                if (pos != std::string::npos && pos == 0)
                {
                    return line.substr(key.length());
                }
            }

            return std::string();
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

        std::string websocketHandshakeResponse =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + getHandshakeResponseKey(webSocketKey)
            + "\r\n"; //to close the response header

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
        
        s.close(clean);
	}	
};

const std::string websocketConnection::magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";