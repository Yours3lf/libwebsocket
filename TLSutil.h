#pragma once

#include "libsocket/Socket.h"

#include <vector>
#include <random>

#ifdef _WIN32
//for SHA1
#include <wincrypt.h>

#pragma comment(lib, "Crypt32")
#else
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include "libwebutil/WebUtil.h"

class TLSsession
{
    SSL* ssl = nullptr;

    static SSL_CTX* ctx;
    static bool inited;
public:
    static void init(const std::string& certificate, const std::string& privateKey)
    {
        if (!inited && !ctx)
        {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            ERR_load_crypto_strings();

            ctx = SSL_CTX_new(TLS_server_method());
            if (!ctx)
            {
                std::cerr << "SSL ctx new failed" << std::endl;
                ERR_print_errors_fp(stderr);
                return;
            }
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
            SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS |
                SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            SSL_CTX_set1_groups_list(ctx, "X25519:P-256");
            // TLS 1.3 suites go through set_ciphersuites; set_cipher_list is 1.2-and-below.
            if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1)
            {
                std::cerr << "SSL ctx set ciphersuites failed" << std::endl;
                ERR_print_errors_fp(stderr);
                return;
            }
            if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305") != 1)
            {
                std::cerr << "SSL ctx set cipher list failed" << std::endl;
                ERR_print_errors_fp(stderr);
                return;
            }

            if (FILE* file = fopen(certificate.c_str(), "r"))
            {
                fclose(file);
            }
            else
            {
                std::cerr << "Can't open certificate using file: " << certificate << std::endl;
            }

            if (FILE* file = fopen(privateKey.c_str(), "r"))
            {
                fclose(file);
            }
            else
            {
                std::cerr << "Can't open privateKey using file: " << privateKey << std::endl;
            }

            if (SSL_CTX_use_certificate_chain_file(ctx, certificate.c_str()) <= 0)
            {
                std::cerr << "SSL ctx use certificate failed" << std::endl;
                ERR_print_errors_fp(stderr);
                return;
            }

            if (SSL_CTX_use_PrivateKey_file(ctx, privateKey.c_str(), SSL_FILETYPE_PEM) <= 0)
            {
                std::cerr << "SSL ctx use privatekey failed" << std::endl;
                ERR_print_errors_fp(stderr);
                return;
            }

            std::cout << "SSL init done" << std::endl;
            ERR_print_errors_fp(stderr);

            inited = true;
        }
    }

    static void cleanup()
    {
        if (inited)
        {
            if(ctx) SSL_CTX_free(ctx);
            EVP_cleanup();
            ERR_free_strings();

            inited = false;
        }
    }

    int receiveMessage(char* buf, int len, bool singleRecv = false)
    {
        if (!inited || !ctx || !ssl) return -1;

        //TODO look into SSL's state machine way of working....

        int bytesReceived = 0;
        while (bytesReceived < len)
        {
            int ret = SSL_read(ssl, buf + bytesReceived, len - bytesReceived);

            if (ret == 0)
            {
                int mode = SSL_get_shutdown(ssl);
                if(mode == SSL_RECEIVED_SHUTDOWN)
                {
                    std::cerr << "SSL receive connection closed by other side" << std::endl;
                    return -3;
                }
                else if(mode == SSL_SENT_SHUTDOWN)
                {
                    std::cerr << "SSL receive connection closed by us" << std::endl;
                    return -2;
                }
                else
                {
                    return -1;
                }
            }
            else if (ret < 0)
            {
                int errorCode = SSL_get_error(ssl, ret);
                if (errorCode == SSL_ERROR_WANT_READ || errorCode == SSL_ERROR_WANT_WRITE)
                {
                    // More socket data is required. Do not spin.
                    return bytesReceived > 0 ? bytesReceived : socket::kWouldBlock;
                }
                else if (errorCode == SSL_ERROR_SYSCALL)
                {
                    uint32_t err = ERR_get_error();

                    if (!err)
                    {
                        // connection was probably just closed abruptly if there's no error
                        return -1;
                    }
                }

                std::cerr << "SSL receive failed " << errorCode << std::endl;
                ERR_print_errors_fp(stderr);
                return -1;
            }

            bytesReceived += ret;

            if (singleRecv)
            {
                break;
            }
        }

        return bytesReceived;
    }

    int sendMessage(const char* buf, int len)
    {
        if (!inited || !ctx || !ssl) return -1;

        int bytesSent = 0;
        while (bytesSent < len)
        {
            int ret = SSL_write(ssl, buf + bytesSent, len - bytesSent);

            if (ret == 0)
            {
                int mode = SSL_get_shutdown(ssl);
                if(mode == SSL_RECEIVED_SHUTDOWN)
                {
                    std::cerr << "SSL send connection closed by other side" << std::endl;
                    return -3;
                }
                else if(mode == SSL_SENT_SHUTDOWN)
                {
                    std::cerr << "SSL send connection closed by us" << std::endl;
                    return -2;
                }
                else
                {
                    return -1;
                }
            }
            else if (ret < 0)
            {
                int errorCode = SSL_get_error(ssl, ret);
                if (errorCode == SSL_ERROR_WANT_READ || errorCode == SSL_ERROR_WANT_WRITE)
                {
                    return bytesSent > 0 ? bytesSent : socket::kWouldBlock;
                }
                else if (errorCode == SSL_ERROR_SYSCALL)
                {
                    uint32_t err = ERR_peek_error();

                    if (!err)
                    {
                        // connection was probably just closed abruptly if there's no error
                        return -1;
                    }
                }

                std::cerr << "SSL send failed " << errorCode << std::endl;
                ERR_print_errors_fp(stderr);
                return -1;
            }

            bytesSent += ret;
        }

        return bytesSent;
    }

    bool handshake(class socket& s)
    {     
        if (!ctx || !inited || ssl) return false;

        ssl =  SSL_new(ctx);
        
        if (!ssl)
        {
            std::cerr << "SSL new failed" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (SSL_set_fd(ssl, *(int*)&s) <= 0)
        {
            std::cerr << "SSL set fd failed" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }

        SSL_set_accept_state(ssl);

        if (SSL_accept(ssl) <= 0)
        {
            std::cerr << "SSL accept failed" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (SSL_do_handshake(ssl) <= 0)
        {
            std::cerr << "SSL do handshake failed" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }

        std::cout << "SSL handshake done" << std::endl;
        ERR_print_errors_fp(stderr);

        return true;
    }

    void close(bool clean = true)
    {
        if (!ssl)
            return;

        if (clean)
        {
            int ret = SSL_shutdown(ssl);
            // ret 0 means the peer close_notify is still outstanding. The TCP
            // socket is closed by the caller, so the SSL object must not leak.
            if (ret < 0)
            {
                int errorCode = SSL_get_error(ssl, ret);
                if (errorCode != SSL_ERROR_WANT_READ && errorCode != SSL_ERROR_WANT_WRITE)
                {
                    std::cerr << "SSL shutdown failed " << errorCode << std::endl;
                    ERR_print_errors_fp(stderr);
                }
            }
        }

        SSL_free(ssl);
        ssl = nullptr;
    }

    TLSsession() = default;

    ~TLSsession()
    {
        if (ssl)
        {
            SSL_free(ssl);
            ssl = nullptr;
        }
    }

    TLSsession(const TLSsession&) = delete;
    TLSsession& operator=(const TLSsession&) = delete;

    TLSsession(TLSsession&& other) noexcept
        : ssl(other.ssl)
    {
        other.ssl = nullptr;
    }

    TLSsession& operator=(TLSsession&& other) noexcept
    {
        if (this != &other)
        {
            close(false);
            ssl = other.ssl;
            other.ssl = nullptr;
        }
        return *this;
    }
};

SSL_CTX* TLSsession::ctx = nullptr;
bool TLSsession::inited = false;