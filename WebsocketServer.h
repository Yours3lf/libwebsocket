#pragma once

#include "WebsocketConnection.h"

#include <unordered_map>

class websocketServer
{
	class socket listeningSocket;
	std::thread listeningThread;
    std::thread messagingThread;

    std::mutex connectionsMutex;
	std::unordered_map<uint32_t, websocketConnection> connections;

    std::mutex sendMessageQueueMutex;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > sendMessageQueue;
    std::mutex receiveMessageQueueMutex;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > receiveMessageQueue;

	bool running = true;
    bool useTLS = false;

    bool (*acceptConnectionCallback)(uint32_t, const std::string&, void*) = 0;
    void* acceptConnectionCallbackDataPtr = 0;

    uint32_t pickID()
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        uint32_t idCandidate = connections.size();
        bool found = true;
        while (found)
        {
            found = connections.find(idCandidate) != connections.end();

            if (found)
            {
                idCandidate++;
            }
        }
        return idCandidate;
    }

	static void listenToConnections(websocketServer* thisPtr, const std::string& address, int port)
	{
#ifndef _WIN32
        pthread_setname_np(pthread_self(), "Listening thread");
#endif

        std::cout << "Listening thread started: " << std::hex << std::this_thread::get_id() << std::dec << std::endl;

        std::cout << "Secure mode: " << (thisPtr->useTLS ? "ON" : "OFF") << std::endl;
        std::cout << "Binding to: " << address << ":" << port << std::endl;

        while (thisPtr->running)
        {
            if (thisPtr->listeningSocket.bind(address, port) == 0)
            {
                std::cout << "Listening... " << std::endl;
                break;
            }

            //likely socket is still in use
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

		while (thisPtr->running)
		{
			thisPtr->listeningSocket.listen();

            std::string address;
            class socket ss = thisPtr->listeningSocket.accept(&address);

            if (ss.isValid())
            {
                std::cout << "Accepted: " << address << std::endl;

                websocketConnection c(std::move(ss));

                std::cout << "Handshake..." << std::endl;

                if (c.handshake(thisPtr->useTLS))
                {
                    std::cout << "Handshake successful" << std::endl;

                    std::string url = c.getURL();
                    
                    uint32_t id = thisPtr->pickID();

                    if (thisPtr->acceptConnectionCallback && thisPtr->acceptConnectionCallback(id, url, thisPtr->acceptConnectionCallbackDataPtr))
                    {
                        std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                        thisPtr->connections.emplace(id, std::move(c));
                    }
                    else 
                    {
                        std::cerr << "Server chose to refuse connection, close connection" << std::endl;
                        c.close(thisPtr->useTLS);
                    }
                }
                else
                {
                    std::cout << "Handshake failed" << std::endl;
                    c.close(thisPtr->useTLS);
                }
            }
		}
	}

    static void handleMessaging(websocketServer* thisPtr)
    {
#ifndef _WIN32
        pthread_setname_np(pthread_self(), "Messaging thread");
#endif

        std::cout << "Messaging thread started: " << std::hex << std::this_thread::get_id() << std::dec << std::endl;

        assert(thisPtr);

        std::thread receiveThread([&]()
            {
#ifndef _WIN32
                pthread_setname_np(pthread_self(), "Receive thread");
#endif
                std::cout << "Receive thread started: " << std::hex << std::this_thread::get_id() << std::dec << std::endl;

                while (thisPtr->running)
                {
                    if (thisPtr->hasConnections())
                    {
                        std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);

                        for (auto& c : thisPtr->connections)
                        {
                            if (c.second.isOpen() && !c.second.receivedAnyBytes()) continue;

                            std::unique_ptr<websocketMessage> m(new websocketMessage());
                            int ret = c.second.receiveWebsocketMessage(*m, thisPtr->useTLS);

                            //error happened
                            if (ret < 0)
                            {
                                //other side closed the connection
                                if (ret == -2)
                                {
                                    std::cerr << "receive connection closed" << std::endl;

                                    m->buf.clear();
                                    m->type = FRAME_CLOSE;
                                    thisPtr->pushMessageReceived(std::make_pair(c.first, std::move(m)));
                                }
                                else
                                {
                                    std::cerr << "receive error " << ret << std::endl;
                                }

                                continue;
                            }

                            switch (m->type)
                            {
                            case FRAME_TEXT:
                            {
                                std::cout << "Text frame received " << m->buf.size() << " bytes" << std::endl;

                                thisPtr->pushMessageReceived(std::make_pair(c.first, std::move(m)));
                                break;
                            }
                            case FRAME_BINARY:
                            {
                                std::cout << "Binary frame received " << m->buf.size() << " bytes" << std::endl;
                                //printRawData(m->buf);

                                thisPtr->pushMessageReceived(std::make_pair(c.first, std::move(m)));
                                break;
                            }
                            default:
                            {
                                std::cerr << "got unknown frame, ignoring" << std::endl;
                                break;
                            }
                            }
                        }
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            });


        std::thread sendThread([&]()
            {
#ifndef _WIN32
                pthread_setname_np(pthread_self(), "Send thread");
#endif
                std::cout << "Send thread started: " << std::hex << std::this_thread::get_id() << std::dec << std::endl;

                while (thisPtr->running)
                {
                    while(!thisPtr->sendMessageQueue.empty())
                    {
                        auto m = thisPtr->popMessageToSend();

                        if (m.second)
                        {
                            std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                            auto it = thisPtr->connections.find(m.first);
                            if (it != thisPtr->connections.end())
                            {
                                int ret = it->second.sendWebsocketMessage(*m.second, thisPtr->useTLS);

                                //error happened
                                if (ret < 0)
                                {
                                    //other side closed the connection
                                    if (ret == -2)
                                    {
                                        std::cerr << "send connection closed" << std::endl;

                                        m.second->buf.clear();
                                        m.second->type = FRAME_CLOSE;
                                        thisPtr->pushMessageReceived(std::move(m));
                                    }
                                    else
                                    {
                                        std::cerr << "send error " << ret << std::endl;
                                    }

                                    continue;
                                }
                            }
                        }
                    };

                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            });

        sendThread.join();
        receiveThread.join();
    }

    std::pair<uint32_t, std::unique_ptr<websocketMessage> > popMessageToSend()
    {
        std::lock_guard<std::mutex> guard(sendMessageQueueMutex);
        if (sendMessageQueue.empty())
        {
            return {};
        }
        auto m = std::move(sendMessageQueue.front());
        sendMessageQueue.pop();
        return m;
    }

    void pushMessageReceived(std::pair<uint32_t, std::unique_ptr<websocketMessage> >  m)
    {
        std::lock_guard<std::mutex> guard(receiveMessageQueueMutex);
        receiveMessageQueue.push(std::move(m));
    }

public:

    websocketServer(bool secure = false) 
    {
        useTLS = secure;
    }

	void run(const std::string& address, int port, bool (*acceptConnectionCallbackPtr)(uint32_t, const std::string&, void*) = 0, void* callbackDataPtr = 0)
	{
        acceptConnectionCallback = acceptConnectionCallbackPtr;
        acceptConnectionCallbackDataPtr = callbackDataPtr;

		listeningThread = std::thread(listenToConnections, this, address, port);
        messagingThread = std::thread(handleMessaging, this);
	}

	void close()
	{
        running = false;
        
        listeningSocket.close();

        std::cout << "Joining listening thread" << std::endl;

        if (listeningThread.joinable())
        {
            listeningThread.join();
        }

        std::cout << "Joining messaging thread" << std::endl;

        if (messagingThread.joinable())
        {
            messagingThread.join();
        }

        std::cout << "Closing all remaining connections" << std::endl;

        {
            std::lock_guard<std::mutex> guard(connectionsMutex);
            for (auto& c : connections)
            {
                c.second.close(useTLS);
            }
            connections.clear();
        }

        std::cout << "Clearing all remaining messages" << std::endl;

        {
            std::lock_guard<std::mutex> guard2(sendMessageQueueMutex);
            while (!sendMessageQueue.empty())
            {
                sendMessageQueue.pop();
            }
        }

        std::lock_guard<std::mutex> guard3(receiveMessageQueueMutex);
        while (!receiveMessageQueue.empty())
        {
            receiveMessageQueue.pop();
        }
	}

    void closeConnection(uint32_t c)
    {
        std::cout << "WebsocketServer close" << std::endl;

        std::lock_guard<std::mutex> guard(connectionsMutex);
        auto it = connections.find(c);
        if(it != connections.end())
        {
            it->second.close(useTLS);
            connections.erase(it);
        }
    }

    std::string getConnectionURL(uint32_t c)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        auto it = connections.find(c);
        if (it != connections.end())
        {
            return it->second.getURL();
        }
        return "";
    }

	bool hasConnections()
	{
        std::lock_guard<std::mutex> guard(connectionsMutex);
		return !connections.empty();
	}

    bool hasMessagesReceived()
    {
        std::lock_guard<std::mutex> guard(receiveMessageQueueMutex);
        return !receiveMessageQueue.empty();
    }

	void broadcastMessage(std::unique_ptr<websocketMessage> m)
	{
        std::lock_guard<std::mutex> guard(connectionsMutex);
		for (auto& c : connections)
		{
            //make a copy for each connection
			pushMessageToSend(std::make_pair(c.first, std::unique_ptr<websocketMessage>(new websocketMessage(*m))));
		}
	}

    void pushMessageToSend(std::pair<uint32_t, std::unique_ptr<websocketMessage> > m)
    {
        std::lock_guard<std::mutex> guard(sendMessageQueueMutex);
        sendMessageQueue.push(std::move(m));
    }

    std::pair<uint32_t, std::unique_ptr<websocketMessage> > popMessageReceived()
    {
        std::lock_guard<std::mutex> guard(receiveMessageQueueMutex);
        if (receiveMessageQueue.empty())
        {
            return {};
        }
        auto m = std::move(receiveMessageQueue.front());
        receiveMessageQueue.pop();
        return m;
    }
};
