#pragma once

#include "libsocket/EventWait.h"
#include "WebsocketConnection.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cassert>
#include <deque>
#include <iostream>
#include <memory>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class websocketServer
{
	struct HandshakeJob
	{
		class socket ss;
		std::string address;
		std::string host;
	};

	class socket listeningSocket;
	std::thread listeningThread;
    std::thread messagingThread;

    std::mutex connectionsMutex;
	std::unordered_map<uint32_t, websocketConnection> connections;
	// Peer address captured at accept, keyed by connection id. The handshake
	// callback runs before the connection is inserted, so the address has to
	// be stored first.
	std::unordered_map<uint32_t, std::string> peerByConn;
    std::mutex connectionsToBeClosedMutex;
    std::queue<std::pair<uint32_t, bool> > connectionsToBeClosed; // connection id, close clean

    std::mutex sendMessageQueueMutex;
    std::condition_variable sendCv;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > sendMessageQueue;
    std::mutex receiveMessageQueueMutex;
    std::queue<std::pair<uint32_t, std::unique_ptr<websocketMessage> > > receiveMessageQueue;

	std::atomic<bool> running{true};
    bool useTLS = false;
    bool permitDeflate = true;
    std::atomic<int> keepaliveIntervalMs{kKeepaliveIntervalMs};
    uint32_t maxFramePayload = kMaxFramePayload;
    uint32_t maxMessageBytes = kMaxMessageBytes;
    // Message cap a new connection starts with; 0 means maxMessageBytes. An owner
    // that authenticates connections starts them small and raises each one with
    // setConnectionMaxMessageBytes, so a client that never authenticates cannot
    // make the server buffer a maxMessageBytes message.
    uint32_t initialMaxMessageBytes = 0;
    std::vector<std::string> subprotocols;

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

    // One host's handshakes: the ones running and the ones waiting their turn.
    struct HandshakeHost
    {
        std::deque<HandshakeJob> waiting;
        uint32_t running = 0;
        // In readyHosts: a job is waiting and a running slot is free.
        bool ready = false;
    };

    std::mutex handshakeMutex;
    std::condition_variable handshakeCv;
    // A handshake holds its thread for its round trips (TLS, then the HTTP request), about
    // half a second on a slow link, and the threads sleep in poll meanwhile. Sixteen let a
    // gateway finish a few dozen handshakes a second, so a reconnect after a restart queued
    // for minutes.
    static const int kHandshakeThreadCount = 64;
    std::thread handshakeThreads[kHandshakeThreadCount];
    // Every handshake ends within kHandshakeTimeoutMs, but a host that opened sockets and
    // sent nothing held every thread until then, and the sockets it kept opening queued
    // ahead of everyone else's. A host now runs a few handshakes at a time, the threads take
    // hosts in turn, and the host's other sockets wait in its own line.
    static const uint32_t kMaxRunningHandshakesPerHost = 4;
    static const size_t kMaxWaitingHandshakesPerHost = 256;
    static const size_t kMaxPendingHandshakes = 4096;
    std::unordered_map<std::string, HandshakeHost> handshakeHosts;
    // Hosts with a handshake to start, in turn order.
    std::deque<std::string> readyHosts;
    // Handshakes waiting or running, all hosts.
    size_t handshakesPending = 0;

    // The host of an accept address ("AF ipv4 203.0.113.8:40000"): the port is dropped. An
    // IPv6 host is keyed by its /64, which one subscriber holds whole, and an IPv4 address
    // carried in IPv6 (::ffff:a.b.c.d on a dual-stack listener) by that IPv4 address.
    static std::string handshakeHostKey(const std::string& address)
    {
        const size_t space = address.rfind(' ');
        std::string host = space == std::string::npos ? address : address.substr(space + 1);
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos)
            host.resize(colon);
        if (address.find(" ipv6 ") == std::string::npos)
            return host;
        in6_addr parsed{};
        if (inet_pton(AF_INET6, host.c_str(), &parsed) != 1)
            return host;
        if (IN6_IS_ADDR_V4MAPPED(&parsed))
            return host.substr(host.rfind(':') + 1);
        static const char kHex[] = "0123456789abcdef";
        std::string key = "ipv6/64 ";
        for (int i = 0; i < 8; ++i)
        {
            key.push_back(kHex[parsed.s6_addr[i] >> 4]);
            key.push_back(kHex[parsed.s6_addr[i] & 0x0f]);
        }
        return key;
    }

    // Puts a host in line when it has a job waiting and a running slot free. Caller holds
    // handshakeMutex.
    void queueHostLocked(const std::string& key, HandshakeHost& host)
    {
        if (host.ready || host.waiting.empty() || host.running >= kMaxRunningHandshakesPerHost)
            return;
        host.ready = true;
        readyHosts.push_back(key);
    }

    // Takes one finished handshake off its host. True when that put the host back in line,
    // so a thread should wake for it. Caller holds handshakeMutex.
    bool finishHandshakeLocked(const std::string& key)
    {
        if (handshakesPending > 0)
            handshakesPending -= 1;
        auto found = handshakeHosts.find(key);
        if (found == handshakeHosts.end())
            return false;
        HandshakeHost& host = found->second;
        if (host.running > 0)
            host.running -= 1;
        if (host.running == 0 && host.waiting.empty())
        {
            handshakeHosts.erase(found);
            return false;
        }
        const bool wasReady = host.ready;
        queueHostLocked(key, host);
        return !wasReady && host.ready;
    }

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
            peerByConn.erase(c);
            return;
        }
        waitSet.remove(c);
        it->second.close(useTLS, clean);
        connections.erase(it);
        peerByConn.erase(c);
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
        std::cout << "Deflate: " << (thisPtr->permitDeflate ? "ON" : "OFF") << std::endl;
        std::cout << "Binding to: " << address << ":" << port << std::endl;

        while (thisPtr->running)
        {
            if (thisPtr->listeningSocket.bind(address, port) == 0)
            {
                std::cout << "Listening... " << std::endl;
                break;
            }

            //likely socket is still in use
            std::cerr << "address already in use, retrying..." << std::endl;
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

                const std::string key = handshakeHostKey(newAddress);
                bool queued = false;
                {
                    std::lock_guard<std::mutex> guard(thisPtr->handshakeMutex);
                    HandshakeHost& host = thisPtr->handshakeHosts[key];
                    if (thisPtr->handshakesPending < kMaxPendingHandshakes &&
                        host.waiting.size() < kMaxWaitingHandshakesPerHost)
                    {
                        HandshakeJob job;
                        job.ss = std::move(ss);
                        job.address = newAddress;
                        job.host = key;
                        host.waiting.push_back(std::move(job));
                        thisPtr->handshakesPending += 1;
                        thisPtr->queueHostLocked(key, host);
                        queued = true;
                    }
                    else if (host.running == 0 && host.waiting.empty())
                        thisPtr->handshakeHosts.erase(key);
                }
                if (!queued)
                {
                    std::cerr << "Too many handshakes waiting, refusing " << newAddress << std::endl;
                    ss.close(false);
                    continue;
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
                    return !thisPtr->readyHosts.empty() || !thisPtr->running;
                });
                if (!thisPtr->running)
                    return;
                const std::string key = std::move(thisPtr->readyHosts.front());
                thisPtr->readyHosts.pop_front();
                auto found = thisPtr->handshakeHosts.find(key);
                if (found == thisPtr->handshakeHosts.end())
                    continue;
                HandshakeHost& host = found->second;
                host.ready = false;
                if (host.waiting.empty())
                    continue;
                job = std::move(host.waiting.front());
                host.waiting.pop_front();
                host.running += 1;
                // Behind every other host that is waiting, if it has more.
                thisPtr->queueHostLocked(key, host);
            }

            std::cout << "Handshake..." << std::endl;

            websocketConnection c(std::move(job.ss));
            {
                std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                const uint32_t startBytes =
                    thisPtr->initialMaxMessageBytes != 0 ? thisPtr->initialMaxMessageBytes : thisPtr->maxMessageBytes;
                c.setLimits(thisPtr->maxFramePayload, startBytes);
                c.setSubprotocols(thisPtr->subprotocols);
            }

            const bool shaken = c.handshake(thisPtr->useTLS, thisPtr->permitDeflate);
            // The slot is given back however the handshake ended. Past this point it is a
            // connection, which maxConnections bounds.
            bool hostReady = false;
            {
                std::lock_guard<std::mutex> guard(thisPtr->handshakeMutex);
                hostReady = thisPtr->finishHandshakeLocked(job.host);
            }
            if (hostReady)
                thisPtr->handshakeCv.notify_one();

            if (!shaken)
            {
                std::cout << "Handshake failed" << std::endl;
                c.close(thisPtr->useTLS);
                continue;
            }

            std::cout << "Handshake successful" << std::endl;

            std::vector<std::unique_ptr<websocketMessage> > early;
            while (c.hasBufferedInput())
            {
                std::unique_ptr<websocketMessage> m(new websocketMessage());
                int drained = c.pump(*m, thisPtr->useTLS, false);
                if (drained > 0)
                    early.push_back(std::move(m));
                else
                    break;
            }

            std::string url = c.getURL();
            uint32_t id = 0;
            {
                std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                id = thisPtr->allocConnIdLocked();
                thisPtr->peerByConn[id] = job.address;
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
                        thisPtr->peerByConn.erase(id);
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
                if (inserted)
                {
                    for (size_t i = 0; i < early.size(); ++i)
                        thisPtr->pushMessageReceived(std::make_pair(id, std::move(early[i])));
                }
                else
                    c.close(thisPtr->useTLS);
            }
            else 
            {
                std::cerr << "Accept callback declined, close connection" << std::endl;
                {
                    std::lock_guard<std::mutex> guard(thisPtr->connectionsMutex);
                    thisPtr->reservedConnIds.erase(id);
                    thisPtr->peerByConn.erase(id);
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

                WaitResult ready[EventWait::kMaxReadyBatch];

                while (thisPtr->running)
                {
                    thisPtr->cleanUpConnections();
                    thisPtr->serviceTimers();

                    int timeout = thisPtr->keepaliveIntervalMs.load();
                    if (timeout <= 0)
                        timeout = -1;
                    int n = thisPtr->waitSet.wait(ready, EventWait::kMaxReadyBatch, timeout);
                    if (!thisPtr->running)
                        break;
                    if (n < 0)
                        continue;
                    if (n == 0)
                        continue;

                    for (int i = 0; i < n; ++i)
                    {
                        uint32_t id = ready[i].id;
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

                        int ret = 0;
                        {
                            std::lock_guard<std::mutex> ioGuard(*io);
                            if (ready[i].writable)
                            {
                                int flushed = connPtr->flushSend(thisPtr->useTLS);
                                bool pending = connPtr->hasPendingSend();
                                connPtr->noteWriteInterest(thisPtr->waitSet, id, pending);
                                if (flushed < 0 && flushed != socket::kWouldBlock)
                                    ret = flushed;
                            }
                            bool readSocket = ready[i].readable || connPtr->hasBufferedInput();
                            while (ret == 0 && readSocket)
                            {
                                std::unique_ptr<websocketMessage> m(new websocketMessage());
                                ret = connPtr->pump(*m, thisPtr->useTLS, true);
                                readSocket = false;
                                if (ret > 0)
                                {
                                    if (m->type == FRAME_TEXT)
                                        std::cout << "Text frame received " << m->buf.size() << " bytes" << std::endl;
                                    else if (m->type == FRAME_BINARY)
                                        std::cout << "Binary frame received " << m->buf.size() << " bytes" << std::endl;
                                    thisPtr->pushMessageReceived(std::make_pair(id, std::move(m)));
                                    ret = 0;
                                    if (connPtr->hasBufferedInput())
                                        readSocket = true;
                                }
                            }
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

                        if (ret == socket::kWouldBlock || ret == 0)
                            continue;

                        if (ret < 0)
                        {
                            if (ret == -3)
                                std::cerr << "receiveWebsocketMessage connection closed by other side" << std::endl;
                            else if (ret == -2)
                                std::cerr << "receiveWebsocketMessage connection closed by us" << std::endl;
                            else if (ret != kCloseQuiet)
                                std::cerr << "receive error " << ret << std::endl;

                            if (ret == -3 || ret == -2)
                            {
                                std::unique_ptr<websocketMessage> closed(new websocketMessage());
                                closed->buf.clear();
                                closed->type = FRAME_CLOSE;
                                thisPtr->pushMessageReceived(std::make_pair(id, std::move(closed)));
                            }

                            if (ret == -3 || ret == -2 || ret == kCloseQuiet)
                            {
                                thisPtr->connectionsToBeClosedMutex.lock();
                                thisPtr->connectionsToBeClosed.push(std::make_pair(id, ret == -2));
                                thisPtr->connectionsToBeClosedMutex.unlock();
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
                            if (connPtr->isOpen())
                                connPtr->noteWriteInterest(thisPtr->waitSet, m.first, connPtr->hasPendingSend());
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

                        if (ret == socket::kWouldBlock)
                            continue;

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

    void serviceTimers()
    {
        auto now = std::chrono::steady_clock::now();
        int interval = keepaliveIntervalMs.load();
        std::vector<uint32_t> ids;
        {
            std::lock_guard<std::mutex> guard(connectionsMutex);
            for (auto& c : connections)
                ids.push_back(c.first);
        }

        for (size_t i = 0; i < ids.size(); ++i)
        {
            uint32_t id = ids[i];
            std::mutex* io = nullptr;
            websocketConnection* connPtr = nullptr;
            {
                std::lock_guard<std::mutex> guard(connectionsMutex);
                auto it = connections.find(id);
                if (it == connections.end() || !it->second.isOpen())
                    continue;
                if (recvInFlight.find(id) != recvInFlight.end() || sendInFlight.find(id) != sendInFlight.end())
                    continue;
                auto mit = connIoMutex.find(id);
                if (mit == connIoMutex.end() || !mit->second)
                    continue;
                io = mit->second.get();
                connPtr = &it->second;
                recvInFlight.insert(id);
            }

            int ret = 0;
            bool timedOut = false;
            {
                std::lock_guard<std::mutex> ioGuard(*io);
                timedOut = connPtr->closeTimedOut(now);
                if (!timedOut)
                    ret = connPtr->serviceKeepalive(useTLS, now, interval);
                if (connPtr->isOpen() && connPtr->hasPendingSend())
                    connPtr->noteWriteInterest(waitSet, id, true);
            }

            {
                std::lock_guard<std::mutex> guard(connectionsMutex);
                recvInFlight.erase(id);
                auto dit = deferredClose.find(id);
                if (dit != deferredClose.end() && sendInFlight.find(id) == sendInFlight.end())
                {
                    bool clean = dit->second;
                    finishCloseLocked(id, clean);
                    continue;
                }
                if (timedOut)
                {
                    finishCloseLocked(id, false);
                    continue;
                }
            }

            if (ret == -2 || ret == -3)
            {
                std::unique_ptr<websocketMessage> closed(new websocketMessage());
                closed->type = FRAME_CLOSE;
                pushMessageReceived(std::make_pair(id, std::move(closed)));
                connectionsToBeClosedMutex.lock();
                connectionsToBeClosed.push(std::make_pair(id, ret == -2));
                connectionsToBeClosedMutex.unlock();
            }
        }
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

    websocketServer(bool secure = false, bool allowDeflate = true)
    {
        useTLS = secure;
        permitDeflate = allowDeflate;
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

        // Sockets still waiting for a handshake thread.
        {
            std::lock_guard<std::mutex> guard(handshakeMutex);
            handshakeHosts.clear();
            readyHosts.clear();
            handshakesPending = 0;
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
            peerByConn.clear();
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
        auto it = connections.find(c);
        if (it == connections.end())
            return;
        int rc = it->second.beginLocalClose(useTLS, clean);
        if (it->second.isOpen() && it->second.hasPendingSend())
            it->second.noteWriteInterest(waitSet, c, true);
        if (rc == kCloseQuiet)
            finishCloseLocked(c, false);
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

    // Address from accept(), including the family prefix and port.
    // Empty when this id was not accepted on this server.
    std::string peerAddress(uint32_t c)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        auto it = peerByConn.find(c);
        if (it == peerByConn.end())
            return "";
        return it->second;
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

    void setPermitDeflate(bool allow)
    {
        permitDeflate = allow;
    }

    void setMaxFramePayload(uint32_t n)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        if (n == 0)
            return;
        maxFramePayload = n;
        for (auto &c : connections)
            c.second.setLimits(n, maxMessageBytes);
    }

    // Startup setting. It also resets every open connection to n, including one
    // raised or lowered with setConnectionMaxMessageBytes.
    void setMaxMessageBytes(uint32_t n)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        if (n == 0)
            return;
        maxMessageBytes = n;
        for (auto &c : connections)
            c.second.setLimits(maxFramePayload, n);
    }

    // Startup setting: the message cap new connections start with (see initialMaxMessageBytes).
    void setInitialMaxMessageBytes(uint32_t n)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        initialMaxMessageBytes = n;
    }

    // Sets one open connection's message cap; 0 means maxMessageBytes. False when
    // the connection is gone. A receive in flight sees the new cap on its next check.
    bool setConnectionMaxMessageBytes(uint32_t c, uint32_t n)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        auto it = connections.find(c);
        if (it == connections.end())
            return false;
        it->second.setLimits(0, n != 0 ? n : maxMessageBytes);
        return true;
    }

    void setKeepaliveIntervalMs(int ms)
    {
        keepaliveIntervalMs.store(ms);
    }

    void setSubprotocols(std::vector<std::string> protocols)
    {
        std::lock_guard<std::mutex> guard(connectionsMutex);
        subprotocols = std::move(protocols);
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
