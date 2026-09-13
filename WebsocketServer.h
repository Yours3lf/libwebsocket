#pragma once

#include "libsocket/EventWait.h"
#include "WebsocketConnection.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <unordered_map>
#include <unordered_set>

class websocketServer
{
	struct HandshakeJob
	{
		class socket ss;
		std::string address;
	};

	class socket listeningSocket;
	std::thread listeningThread;
    std::thread messagingThread;

    std::mutex connectionsMutex;
	std::unordered_map<uint32_t, websocketConnection> connections;
    std::mutex connectionsToBeClosedMutex;
    std::queue<std::pair<uint32_t, bool> > connectionsToBeClosed; // connection id, close clean

    std::mutex sendMessageQueueMutex;
    std::condition_variable sendCv;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > sendMessageQueue;
    std::mutex receiveMessageQueueMutex;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > receiveMessageQueue;

	bool running = true;
    bool useTLS = false;

    bool (*acceptConnectionCallback)(uint32_t, const std::string&, void*) = nullptr;
    void* acceptConnectionCallbackDataPtr = nullptr;
    void (*messageReceivedHook)(void*) = nullptr;
    void* messageReceivedHookData = nullptr;

    EventWait waitSet;
    std::unordered_map<uint32_t, std::unique_ptr<std::mutex> > connIoMutex;
    std::unordered_set<uint32_t> recvInFlight;
    std::unordered_set<uint32_t> sendInFlight;
    std::atomic<uint32_t> nextConnId{0};
    uint32_t maxConnections = 500000;

    std::mutex handshakeMutex;
    std::condition_variable handshakeCv;
    std::queue<HandshakeJob> handshakeQueue;
    static const int kHandshakeThreadCount = 4;
    std::thread handshakeThreads[4];

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

    std::unordered_set<uint32_t> reservedConnIds;
    std::unordered_map<uint32_t, bool> deferredClose;

    uint32_t allocConnIdLocked()
    {
        for (uint32_t n = 0; n < 0x00FFFFFFu; ++n)
        {
            uint32_t id = nextConnId.fetch_add(1) & 0x00FFFFFFu;
            if (connections.find(id) == connections.end() && reservedConnIds.find(id) == reservedConnIds.end())
            {
                reservedConnIds.insert(id);
                return id;
            }
            (void)n;
        }
        uint32_t id = nextConnId.fetch_add(1) & 0x00FFFFFFu;
        reservedConnIds.insert(id);
        return id;
    }

    void finishCloseLocked(uint32_t c, bool clean)
    {
        auto it = connections.find(c);
        if (it == connections.end())
        {
            reservedConnIds.erase(c);
            deferredClose.erase(c);
            return;
        }
        waitSet.remove(c);
        it->second.close(useTLS, clean);
        connections.erase(it);
        connIoMutex.erase(c);
        reservedConnIds.erase(c);
        deferredClose.erase(c);
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

            std::string newAddress;
            class socket ss = thisPtr->listeningSocket.accept(&newAddress);

            if (ss.isValid())
            {
                std::cout << "Accepted: " << newAddress << std::endl;

                if (thisPtr->hasConnections() && thisPtr->connectionCount() >= thisPtr->maxConnections)
                {
                    std::cerr << "Too many connections " << thisPtr->connectionCount() << "/" << thisPtr->maxConnections << std::endl;
                    ss.close(false);
                    continue;
                }

                HandshakeJob job;
                job.ss = std::move(ss);
                job.address = newAddress;
                {
                    std::lock_guard<std::mutex> guard(thisPtr->handshakeMutex);
                    thisPtr->handshakeQueue.push(std::move(job));
                }
                thisPtr->handshakeCv.notify_one();
            }
            else
            {
                std::cerr << "Listener got new connection, but handle is invalid." << std::endl; //
            }
		}
	}

    static void handshakeWorker(websocketServer* thisPtr)
    {
#ifndef _WIN32
        pthread_setname_np(pthread_self(), "Handshake");
#endif

        while (thisPtr->running)
        {
            HandshakeJob job;
            {
                std::unique_lock<std::mutex> lock(thisPtr->handshakeMutex);
                thisPtr->handshakeCv.wait(lock, [thisPtr]()
                {
                    return !thisPtr->handshakeQueue.empty() || !thisPtr->running;
                });
                if (!thisPtr->running && thisPtr->handshakeQueue.empty())
                    return;
                if (thisPtr->handshakeQueue.empty())
                    continue;
                job = std::move(thisPtr->handshakeQueue.front());
                thisPtr->handshakeQueue.pop();
            }

            std::cout << "Handshake..." << std::endl;

            websocketConnection c(std::move(job.ss));

            if (!c.handshake(thisPtr->useTLS))
            {
                std::cout << "Handshake failed" << std::endl;
                c.close(thisPtr->useTLS);
                continue;
            }

            std::cout << "Handshake successful" << std::endl;

            std::string url = c.getURL();
            uint32_t id = 0;
            {
                std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                id = thisPtr->allocConnIdLocked();
            }

            if(!thisPtr->acceptConnectionCallback ||
                (thisPtr->acceptConnectionCallback &&
                thisPtr->acceptConnectionCallback(id, url, thisPtr->acceptConnectionCallbackDataPtr)))
            {
                bool inserted = false;
                {
                    std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                    if (thisPtr->connections.size() >= thisPtr->maxConnections)
                    {
                        std::cerr << "Too many connections " << thisPtr->connections.size() << "/" << thisPtr->maxConnections << std::endl;
                        thisPtr->reservedConnIds.erase(id);
                    }
                    else
                    {
                        auto added = thisPtr->connections.emplace(id, std::move(c));
                        assert(added.second);
                        added.first->second.addToWaitSet(thisPtr->waitSet, id);
                        thisPtr->connIoMutex[id] = std::unique_ptr<std::mutex>(new std::mutex());
                        thisPtr->reservedConnIds.erase(id);
                        inserted = true;
                    }
                }
                if (!inserted)
                    c.close(thisPtr->useTLS);
            }
            else 
            {
                std::cerr << "Accept callback declined, close connection" << std::endl;
                {
                    std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                    thisPtr->reservedConnIds.erase(id);
                }
                c.close(thisPtr->useTLS);
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

                uint32_t ready[64];

                while (thisPtr->running)
                {
                    thisPtr->cleanUpConnections();

                    // connection ids, not poll-all / per-socket descriptors
                    int n = thisPtr->waitSet.wait(ready, 64, -1);
                    if (!thisPtr->running)
                        break;
                    if (n <= 0)
                        continue;

                    for (int i = 0; i < n; ++i)
                    {
                        uint32_t id = ready[i];
                        std::mutex* io = nullptr;
                        websocketConnection* connPtr = nullptr;
                        {
                            std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                            auto it = thisPtr->connections.find(id);
                            if (it == thisPtr->connections.end() || !it->second.isOpen())
                                continue;
                            auto mit = thisPtr->connIoMutex.find(id);
                            if (mit == thisPtr->connIoMutex.end() || !mit->second)
                                continue;
                            io = mit->second.get();
                            connPtr = &it->second;
                            thisPtr->recvInFlight.insert(id);
                        }

                        std::unique_ptr<websocketMessage> m(new websocketMessage());
                        int ret = 0;
                        {
                            std::lock_guard<std::mutex> ioGuard(*io);
                            ret = connPtr->receiveWebsocketMessage(*m, thisPtr->useTLS);
                        }

                        {
                            std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                            thisPtr->recvInFlight.erase(id);
                            auto dit = thisPtr->deferredClose.find(id);
                            if (dit != thisPtr->deferredClose.end() &&
                                thisPtr->sendInFlight.find(id) == thisPtr->sendInFlight.end())
                            {
                                bool clean = dit->second;
                                thisPtr->finishCloseLocked(id, clean);
                            }
                        }

                        //error happened
                        if (ret < 0)
                        {
                            //other side closed the connection
                            if (ret == -3)
                            {
                                std::cerr << "receiveWebsocketMessage connection closed by other side" << std::endl;
                            }
                            else if(ret == -2)
                            {
                                std::cerr << "receiveWebsocketMessage connection closed by us" << std::endl;
                            }
                            else
                            {
                                std::cerr << "receive error " << ret << std::endl;
                            }

                            if(ret == -3 || ret == -2)
                            {
                                m->buf.clear();
                                m->type = FRAME_CLOSE;
                                thisPtr->pushMessageReceived(std::make_pair(id, std::move(m)));

                                thisPtr->connectionsToBeClosedMutex.lock();
                                thisPtr->connectionsToBeClosed.push(std::make_pair(id, ret == -2));
                                thisPtr->connectionsToBeClosedMutex.unlock();
                            }

                            continue;
                        }

                        switch (m->type)
                        {
                        case FRAME_TEXT:
                        {
                            std::cout << "Text frame received " << m->buf.size() << " bytes" << std::endl;

                            thisPtr->pushMessageReceived(std::make_pair(id, std::move(m)));
                            break;
                        }
                        case FRAME_BINARY:
                        {
                            std::cout << "Binary frame received " << m->buf.size() << " bytes" << std::endl;
                            //printRawData(m->buf);

                            thisPtr->pushMessageReceived(std::make_pair(id, std::move(m)));
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
            });


        std::thread sendThread([&]()
            {
#ifndef _WIN32
                pthread_setname_np(pthread_self(), "Send thread");
#endif
                std::cout << "Send thread started: " << std::hex << std::this_thread::get_id() << std::dec << std::endl;

                while (thisPtr->running)
                {
                    std::pair<uint32_t, std::unique_ptr<websocketMessage> > m;
                    {
                        std::unique_lock<std::mutex> lock(thisPtr->sendMessageQueueMutex);
                        thisPtr->sendCv.wait(lock, [thisPtr]()
                        {
                            return !thisPtr->sendMessageQueue.empty() || !thisPtr->running;
                        });
                        if (!thisPtr->running && thisPtr->sendMessageQueue.empty())
                            break;
                        if (thisPtr->sendMessageQueue.empty())
                            continue;
                        m = std::move(thisPtr->sendMessageQueue.front());
                        thisPtr->sendMessageQueue.pop();
                    }

                    if (m.second)
                    {
                        thisPtr->cleanUpConnections();

                        std::mutex* io = nullptr;
                        websocketConnection* connPtr = nullptr;
                        {
                            std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                            auto it = thisPtr->connections.find(m.first);
                            if (it != thisPtr->connections.end())
                            {
                                auto mit = thisPtr->connIoMutex.find(m.first);
                                if (mit != thisPtr->connIoMutex.end() && mit->second)
                                {
                                    io = mit->second.get();
                                    connPtr = &it->second;
                                    thisPtr->sendInFlight.insert(m.first);
                                }
                            }
                        }

                        if (!connPtr || !io)
                            continue;

                        int ret = 0;
                        {
                            std::lock_guard<std::mutex> ioGuard(*io);
                            ret = connPtr->sendWebsocketMessage(*m.second, thisPtr->useTLS);
                        }

                        {
                            std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                            thisPtr->sendInFlight.erase(m.first);
                            auto dit = thisPtr->deferredClose.find(m.first);
                            if (dit != thisPtr->deferredClose.end() &&
                                thisPtr->recvInFlight.find(m.first) == thisPtr->recvInFlight.end())
                            {
                                bool clean = dit->second;
                                thisPtr->finishCloseLocked(m.first, clean);
                            }
                        }

                        //error happened
                        if (ret < 0)
                        {
                            //other side closed the connection
                            if (ret == -3)
                            {
                                std::cerr << "sendWebsocketMessage connection closed by other side" << std::endl;
                            }
                            else if(ret == -2)
                            {
                                std::cerr << "sendWebsocketMessage connection closed by us" << std::endl;
                            }
                            else
                            {
                                std::cerr << "send error " << ret << std::endl;
                            }

                            if(ret == -3 || ret == -2)
                            {
                                m.second->buf.clear();
                                m.second->type = FRAME_CLOSE;
                                thisPtr->pushMessageReceived(std::move(m));

                                thisPtr->connectionsToBeClosedMutex.lock();
                                thisPtr->connectionsToBeClosed.push(std::make_pair(m.first, ret == -2));
                                thisPtr->connectionsToBeClosedMutex.unlock();
                            }

                            continue;
                        }
                    }
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
        if (messageReceivedHook)
            messageReceivedHook(messageReceivedHookData);
    }

    void cleanUpConnections()
    {
        std::lock_guard<std::mutex> guard(connectionsToBeClosedMutex);

        while (!this->connectionsToBeClosed.empty())
        {
            auto candidate = this->connectionsToBeClosed.front();
            this->connectionsToBeClosed.pop();
            this->closeConnection(candidate.first, candidate.second);
        }
    }

public:

    websocketServer(bool secure = false) 
    {
        useTLS = secure;
    }

	void run(const std::string& address, int port, bool (*acceptConnectionCallbackPtr)(uint32_t, const std::string&, void*) = nullptr, void* callbackDataPtr = nullptr)
	{
        acceptConnectionCallback = acceptConnectionCallbackPtr;
        acceptConnectionCallbackDataPtr = callbackDataPtr;

        if (!waitSet.init())
        {
            std::cerr << "EventWait init failed" << std::endl;
            return;
        }

        for (int i = 0; i < kHandshakeThreadCount; ++i)
            handshakeThreads[i] = std::thread(handshakeWorker, this);

		listeningThread = std::thread(listenToConnections, this, address, port);
        messagingThread = std::thread(handleMessaging, this);
	}

	void close()
	{
        running = false;

        waitSet.wakeup();
        sendCv.notify_all();
        handshakeCv.notify_all();
        
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

        for (int i = 0; i < kHandshakeThreadCount; ++i)
        {
            if (handshakeThreads[i].joinable())
                handshakeThreads[i].join();
        }

        std::cout << "Closing all remaining connections" << std::endl;

        {
            std::lock_guard<std::mutex> guard(connectionsMutex);
            for (auto& c : connections)
            {
                waitSet.remove(c.first);
                c.second.close(useTLS);
            }
            connections.clear();
            connIoMutex.clear();
            recvInFlight.clear();
            sendInFlight.clear();
        }

        waitSet.close();

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

    void closeConnection(uint32_t c, bool clean = true)
    {
        std::cout << "WebsocketServer close" << std::endl;

        std::lock_guard<std::mutex> guard(connectionsMutex);
        if (recvInFlight.find(c) != recvInFlight.end() || sendInFlight.find(c) != sendInFlight.end())
        {
            deferredClose[c] = clean;
            return;
        }
        finishCloseLocked(c, clean);
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

    uint32_t connectionCount()
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        return uint32_t(connections.size());
    }

    void setMaxConnections(uint32_t n)
    {
        maxConnections = n;
    }

    void setMessageReceivedHook(void (*fn)(void*), void* data)
    {
        messageReceivedHook = fn;
        messageReceivedHookData = data;
    }

    EventWaitBackend waitBackend() const
    {
        return waitSet.backend();
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
        sendCv.notify_one();
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
