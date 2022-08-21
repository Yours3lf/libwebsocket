#pragma once

#include "Socket.h"
#include "WebsocketMessage.h"

#include <vector>
#include <thread>
#include <queue>
#include <mutex>

class websocketConnection
{
	friend class websocketServer;

private:

	class socket s;
	std::thread t;

	union header
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

	std::mutex sendMessageQueueMutex;
	std::queue<websocketMessage*> sendMessageQueue;
	std::mutex receiveMessageQueueMutex;
	std::queue<websocketMessage*> receiveMessageQueue;

	static void receiveAllData(std::vector<char>& buf, class socket& s)
	{
		buf.clear();
		int receiveBufOffset = 0;
		int bytesReceived = 0;

		//Websocket frames can be massive, we'll just read them 64kb at a time
		while (bytesReceived == buf.size() - receiveBufOffset)
		{
			receiveBufOffset += bytesReceived;
			buf.resize(buf.size() + 65535);
			bytesReceived = s.receive(buf.data() + receiveBufOffset, buf.size() - receiveBufOffset);
		}
	}

	static uint16_t swapEndianness(uint16_t x)
	{
		uint16_t converted = 0;
		converted |= (0x00ff & x) << 8;
		converted |= (0xff00 & x) >> 8;
		return converted;
	}

	static uint32_t swapEndianness(uint32_t x)
	{
		uint32_t converted = 0;
		converted |= (0x000000ff & x) << 24;
		converted |= (0x0000ff00 & x) << 8;
		converted |= (0x00ff0000 & x) >> 8;
		converted |= (0xff000000 & x) >> 24;
		return converted;
	}

	static uint64_t swapEndianness(uint64_t x)
	{
		uint64_t converted = 0;
		converted |= (0x00000000000000ffull & x) << 56;
		converted |= (0x000000000000ff00ull & x) << 40;
		converted |= (0x0000000000ff0000ull & x) << 24;
		converted |= (0x00000000ff000000ull & x) << 8;
		converted |= (0x000000ff00000000ull & x) >> 8;
		converted |= (0x0000ff0000000000ull & x) >> 24;
		converted |= (0x00ff000000000000ull & x) >> 40;
		converted |= (0xff00000000000000ull & x) >> 56;
		return converted;
	}

	//extract bits from a 32bit value
	// first/last inclusive
	//first bit 0..31
	//last  bit 0..31
	static uint32_t extractBitRange(uint32_t data, uint8_t firstBit, uint8_t lastBit)
	{
		assert(lastBit >= firstBit);
		assert(firstBit >= 0 && firstBit <= 31);
		assert(lastBit >= 0 && lastBit <= 31);
		return (data >> firstBit) & ~(~0ull << (lastBit - firstBit + 1));
	}

	void receiveWebsocketMessage(class socket& s, websocketMessage& m)
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

		 //Websocket frames may come in multiple messages
		 //Indicated by the fin bit whether it's the last one or not
		bool fin = false;
		while (!fin)
		{
			std::vector<char> receiveBuf;
			receiveAllData(receiveBuf, s);

			uint32_t payloadByteOffset = 0;

			uint16_t websocketFrameHeader = *(uint16_t*)receiveBuf.data();
			header h = *(header*)&websocketFrameHeader;

			fin = h.fin;
			uint64_t payloadLen = h.payloadLen;

			if (fin)
			{
				m.type = (frameType)h.opcode;
			}

			payloadByteOffset += sizeof(websocketFrameHeader);

			if (payloadLen == 126)
			{
				uint16_t payloadLen16 = *(uint16_t*)(receiveBuf.data() + payloadByteOffset);
				payloadByteOffset += sizeof(uint16_t);

				payloadLen = swapEndianness(payloadLen16);
				//std::cout << "Extended payload len bytes: " << payloadLen << std::endl;
			}
			else if (payloadLen == 127)
			{
				payloadLen = *(uint64_t*)(receiveBuf.data() + payloadByteOffset);
				payloadByteOffset += sizeof(uint64_t);

				payloadLen = swapEndianness(payloadLen);
				//std::cout << "Extended payload len bytes: " << payloadLen << std::endl;
			}

			//client to server comms must be masked
			assert(h.masked);

			uint8_t mask[4];
			for (int c = 0; c < 4; ++c)
			{
				mask[c] = *(uint8_t*)(receiveBuf.data() + payloadByteOffset + c);
			}
			payloadByteOffset += 4 * sizeof(uint8_t);

			char* encodedData = receiveBuf.data() + payloadByteOffset;

			//decode xor encryption
			std::vector<char> decodedData(payloadLen);
			for (uint64_t c = 0; c < payloadLen; ++c)
			{
				decodedData[c] = encodedData[c] ^ mask[c % 4];
			}

			m.buf.insert(std::end(m.buf), decodedData.begin(), decodedData.end());

			//decodedData[payloadLen] = '\0';
			//std::cout << "Message: " << std::endl << decodedData.data() << std::endl;
		}
	}

	void sendWebsocketMessage(class socket& s, const websocketMessage& m)
	{
		std::vector<char> outBuf;

		header h = {};
		h.opcode = m.type; //frame type
		h.masked = false; //server must send unmasked
		h.fin = true; //we'll just send one frame to keep it simple, it can be huge anyways

		if (m.buf.size() < 126)
		{
			h.payloadLen = m.buf.size();

			outBuf.resize(sizeof(h) + m.buf.size());

			*(header*)outBuf.data() = h;

			memcpy(outBuf.data() + sizeof(h), m.buf.data(), m.buf.size());
		}
		else if (m.buf.size() < ~uint16_t(0))
		{
			h.payloadLen = 126;
			uint16_t extendedPayloadLen = m.buf.size();
			uint16_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

			outBuf.resize(sizeof(h) + sizeof(uint16_t) + m.buf.size());

			*(header*)outBuf.data() = h;

			*(uint16_t*)(outBuf.data() + sizeof(h)) = extendedPayloadLenBE;

			memcpy(outBuf.data() + sizeof(h) + sizeof(uint16_t), m.buf.data(), m.buf.size());
		}
		else
		{
			assert(m.buf.size() < (~0ull >> 1));

			h.payloadLen = 127;
			uint64_t extendedPayloadLen = m.buf.size();
			uint64_t extendedPayloadLenBE = swapEndianness(extendedPayloadLen);

			outBuf.resize(sizeof(h) + sizeof(uint64_t) + m.buf.size());

			*(header*)outBuf.data() = h;

			*(uint64_t*)(outBuf.data() + sizeof(h)) = extendedPayloadLenBE;

			memcpy(outBuf.data() + sizeof(h) + sizeof(uint64_t), m.buf.data(), m.buf.size());
		}

		s.send(outBuf.data(), outBuf.size());
	}

	websocketMessage* popMessageToSend()
	{
		std::lock_guard<std::mutex> guard(sendMessageQueueMutex);
		if (sendMessageQueue.empty())
		{
			return 0;
		}
		websocketMessage* m = sendMessageQueue.front();
		sendMessageQueue.pop();
		return m;
	}

	void pushMessageReceived(websocketMessage* m)
	{
		std::lock_guard<std::mutex> guard(receiveMessageQueueMutex);
		receiveMessageQueue.push(m);
	}

public:

	void pushMessageToSend(websocketMessage* m)
	{
		std::lock_guard<std::mutex> guard(sendMessageQueueMutex);
		sendMessageQueue.push(m);
	}

	websocketMessage* popMessageReceived()
	{
		std::lock_guard<std::mutex> guard(receiveMessageQueueMutex);
		if (receiveMessageQueue.empty())
		{
			return 0;
		}
		websocketMessage* m = receiveMessageQueue.front();
		receiveMessageQueue.pop();
		return m;
	}

	websocketConnection(class socket&& ss)
	{
		s = std::move(ss);
	}

	void close()
	{
		t.join();

		websocketMessage m;
		m.type = FRAME_CLOSE;
		sendWebsocketMessage(s, m);

		s.close();

		while(!sendMessageQueue.empty())
		{
			auto m = sendMessageQueue.front();
			free(m);
			sendMessageQueue.pop();
		}

		while (!receiveMessageQueue.empty())
		{
			auto m = receiveMessageQueue.front();
			free(m);
			receiveMessageQueue.pop();
		}
	}

	void run()
	{
		t = std::thread(websocketConnection::messagingThread, this);
	}

	static void messagingThread(websocketConnection* thisPtr)
	{
		assert(thisPtr);

		bool running = true;

		std::thread receiveThread([&]()
			{
				while (running)
				{
					websocketMessage* m = new websocketMessage();
					thisPtr->receiveWebsocketMessage(thisPtr->s, *m);

					switch (m->type)
					{
					case FRAME_TEXT:
					case FRAME_BINARY:
						thisPtr->pushMessageReceived(m);
						break;
					case FRAME_CLOSE:
						running = false;
						thisPtr->pushMessageReceived(m);
						break;
					case FRAME_PING:
					{
						websocketMessage* mm = new websocketMessage();
						mm->type = FRAME_PONG;
						thisPtr->pushMessageToSend(mm);
						free(m);
						break;
					}
					case FRAME_PONG:
						free(m);
						break;
					default:
						free(m);
						break;
					}
				}
			});


		std::thread sendThread([&]()
			{
				while (running)
				{
					websocketMessage* m = thisPtr->popMessageToSend();

					if (m)
					{
						thisPtr->sendWebsocketMessage(thisPtr->s, *m);
						free(m);
					}
					else
					{
						//sleep for 10ms if there are no messages to send
						Sleep(10);
					}
				}
			});

		sendThread.join();
		receiveThread.join();
	}
};