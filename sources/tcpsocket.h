#pragma once

#include <string>
#include <cstdint>

#if USE_SSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#endif    // USE_SSL

/*-----------------------------------------------------------------------------
    Portability
-----------------------------------------------------------------------------*/

// Use Winsock2 on Windows
#ifdef WIN32

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>

// Make Unix types behave as Winsock2
#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)

typedef int                SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr    SOCKADDR;
typedef struct in_addr     IN_ADDR;

#endif

/*-----------------------------------------------------------------------------
    Socket class definition
-----------------------------------------------------------------------------*/

class TcpSocket
{

public:
	TcpSocket();

private:
	// This constructor is dedicated to forking the server socket when accepting a client
#if USE_SSL
	TcpSocket(SOCKET socket, sockaddr_in clientInfo, SSL* pSession = nullptr);
#else
	TcpSocket(SOCKET socket, sockaddr_in clientInfo);
#endif    // USE_SSL

public:
	// Copy & assignment constructors
	TcpSocket(const TcpSocket& o);
	TcpSocket& operator=(const TcpSocket& o);

	// Destructor
	~TcpSocket();

#if USE_SSL

	enum class SSLVerifyMethod : uint8_t
	{
		FullVerification,        // Let OpenSSL run all checks on the server certificate
		DomainAndCertificate,    // Verify the domain name and certificate chain
		AcceptSelfSigned         // Verify the domain name and certificate, accept self-signed certificates
	};

	// Setup this socket to work as a SSL server
	bool InitializeSSLServer(const std::string& certFile, const std::string& keyFile);

	// Setup this socket to work as a SSL client with an optional explicit CA certificate file
	bool InitializeSSLClient(SSLVerifyMethod verifyMethod = SSLVerifyMethod::FullVerification, const std::string& caCertsFile = "");

#endif    // USE_SSL

	// Connect to the server at domain:port
	bool Connect(const std::string& domain, uint16_t port = 80);

	// Start listening on port
	bool Listen(uint16_t port, uint32_t clients = 10);

	// Wait for connection, accept when it arrives
	const TcpSocket Accept();

	// is this socket OK ?
	bool IsValid() const;

	// Write data on the socket
	bool Write(const std::string& data);

	// Read data from the socket
	bool Read(std::string& data);

	// Get the IP address of the connected client
	std::string GetClientAddress() const;

	// Terminate the connection
	void Close();

private:
	// Setup the infrastructure
	static void Initialize();

	// Release static data
	static void Shutdown();

	// Get the last error code
	static int GetErrno();

private:
	int*        mRefCount;
	SOCKET      mSocket;
	sockaddr_in mClientInfo;

#if USE_SSL
	SSL_CTX*        mSSLContext;
	SSL*            mSSLSession;
	SSLVerifyMethod mSSLVerify;
#endif    // USE_SSL

	static int      sSocketCount;
	static addrinfo sConnectHints;
	static addrinfo sListenHints;

	static const int cBufferSize = 16384;
	static const int cPortSize   = 15;
};
