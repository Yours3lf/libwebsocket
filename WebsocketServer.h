#pragma once

#include "libsocket/Socket.h"

#include "WebsocketConnection.h"

#include <vector>
#include <list>

#ifdef _WIN32
//for SHA1
#include <wincrypt.h>

#pragma comment(lib, "Crypt32")
#else
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#endif


class websocketServer
{
	class socket listeningSocket;
	std::thread listeningThread;
	std::list<websocketConnection> connections;

	bool running = true;

	const static std::string magicString;

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

		return std::string(hashStrBuf.data());
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
			memcpy(hashStrBuf.data(), bptr->data, bptr->length-1);
			hashStrBuf[bptr->length-1] = 0;

			BIO_free_all(b64);
		}
		return std::string(hashStrBuf.data());
#endif
	}

	bool handshake(websocketConnection& c)
	{
		std::vector<std::string> headerLines;
		{
			//we'll assume the handshake fits into 64kb
			std::vector<char> receiveBuf;
			receiveBuf.resize(65535);
			c.s.receive(receiveBuf.data(), receiveBuf.size());

			splitHeader(receiveBuf.data(), headerLines);
		}

		//find websocket key in header
		std::string webSocketKey;
		for (auto line : headerLines)
		{
			std::string keystr = "Sec-WebSocket-Key: ";
			size_t pos = line.find(keystr);
			if (pos != std::string::npos && pos == 0)
			{
				webSocketKey = line.substr(keystr.length());
				break;
			}
		}

		//prepare websocket handshake response
		webSocketKey += magicString;

		std::string websocketHandshakeResponse =
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection : Upgrade\r\n"
			"Sec-WebSocket-Accept : " + getHandshakeResponseKey(webSocketKey)
			+ "\r\n"; //to close the response header

		c.s.send(websocketHandshakeResponse.data(), websocketHandshakeResponse.length());

		//could return false to reject invalid handshakes
		return true;
	}

	static void listenToConnections(websocketServer* thisPtr, const std::string& address, int port)
	{
		thisPtr->listeningSocket.bind(address, port);

		std::cout << "Websocket server listening on: " << address << ":" << port << std::endl;

		while (thisPtr->running)
		{
			thisPtr->listeningSocket.listen();

			class socket ss = thisPtr->listeningSocket.accept();

			if (ss.isValid())
			{
				thisPtr->connections.emplace_back(std::move(ss));

				bool res = thisPtr->handshake(thisPtr->connections.back());

				if (res)
				{
					thisPtr->connections.back().run();
				}
				else
				{
					thisPtr->connections.back().close();
					thisPtr->connections.pop_back();
				}
			}
		}
	}

public:

	void run(const std::string& address, int port)
	{
		listeningThread = std::thread(listenToConnections, this, address, port);
	}

	void close()
	{
		for (auto& c : connections)
		{
			c.close();
		}

		connections.clear();

		running = false;
		listeningSocket.close();
		listeningThread.join();
	}

	bool hasConnections()
	{
		return !connections.empty();
	}

	void broadcastMessage(websocketMessage* m)
	{
		for (auto& c : connections)
		{
			c.pushMessageToSend(m);
		}
	}

	void receiveMessages(std::vector<websocketMessage*>& m)
	{
		for (auto& c : connections)
		{
			websocketMessage* mm = 0;
			if (mm = c.popMessageReceived())
			{
				m.push_back(mm);
			}
		}
	}
};

const std::string websocketServer::magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
