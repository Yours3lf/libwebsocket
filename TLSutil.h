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

void printRawData(const char* raw, int len)
{
    for (int c = 0; c < len; ++c)
    {
        printf("%02x ", raw[c]);
    }
    printf("\n");
}

void printRawData(const std::vector<char>& raw)
{
    for (int c = 0; c < raw.size(); ++c)
    {
        printf("%02x ", raw[c]);
    }
    printf("\n");
}

void printRawData(const std::vector<uint8_t>& raw)
{
    for (int c = 0; c < raw.size(); ++c)
    {
        printf("%02x ", raw[c]);
    }
    printf("\n");
}

template<typename t>
static t* getRawData(const std::vector<char>& data, uint32_t& payloadByteOffset, uint32_t length = 0)
{
    t* d = (t*)(data.data() + payloadByteOffset);

    if (length != 0)
    {
        payloadByteOffset += length;
    }
    else 
    {
        payloadByteOffset += sizeof(t);
    }

    //make sure we don't overrun our buffer
    if (payloadByteOffset > data.size()) { return 0;  }

    return d;
}

template<typename t>
static void derefRawData(t* raw, t& candidate)
{
    assert(raw);

    if (raw) 
    {
        candidate = *raw;
    }
}

template<typename t>
static void setRawData(std::vector<char>& buf, const t* data, uint32_t length = 0)
{
    assert(data);

    uint32_t curSize = buf.size();
    uint32_t payloadSize = (length != 0 ? length : sizeof(t));

    buf.resize(buf.size() + payloadSize);
    memcpy(buf.data() + curSize, data, payloadSize);
}

class TLSsession
{
    SSL* ssl = 0;

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
            SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
            SSL_CTX_set1_groups_list(ctx, "X25519");
            SSL_CTX_set_cipher_list(ctx, "TLS_AES_128_GCM_SHA256");

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

            if (SSL_CTX_use_certificate_file(ctx, certificate.c_str(), SSL_FILETYPE_PEM) <= 0)
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
                std::cerr << "SSL receive connection closed" << std::endl;
                return -2;
            }
            else if (ret < 0)
            {
                int errorCode = SSL_get_error(ssl, ret);
                if (errorCode == SSL_ERROR_WANT_READ || errorCode == SSL_ERROR_WANT_WRITE)
                {
                    continue; //Try again
                }

                std::cerr << "SSL receive failed" << std::endl;
                ERR_print_errors_fp(stderr);
            }

            bytesReceived += ret;

            if (singleRecv)
            {
                break;
            }
        }

        return bytesReceived;
    }

    int sendMessage(char* buf, int len)
    {
        if (!inited || !ctx || !ssl) return -1;

        int bytesSent = 0;
        while (bytesSent < len)
        {
            int ret = SSL_write(ssl, buf + bytesSent, len - bytesSent);

            if (ret == 0)
            {
                std::cerr << "SSL send connection closed" << std::endl;
                return -2;
            }
            else if (ret < 0)
            {
                int errorCode = SSL_get_error(ssl, ret);
                if (errorCode == SSL_ERROR_WANT_READ || errorCode == SSL_ERROR_WANT_WRITE)
                {
                    continue; //Try again
                }

                std::cerr << "SSL send failed" << std::endl;
                ERR_print_errors_fp(stderr);
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

    void close()
    {
        if(ssl) SSL_free(ssl);
    }
};

SSL_CTX* TLSsession::ctx = 0;
bool TLSsession::inited = false;