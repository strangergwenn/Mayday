#include "tcpsocket.h"
#include <iostream>
#include <cassert>

#if USE_SSL
#include "certs.h"
#endif    // USE_SSL

/*-----------------------------------------------------------------------------
    Constructors & destructor
-----------------------------------------------------------------------------*/

TcpSocket::TcpSocket()
	: mSocket(SOCKET_ERROR)
#if USE_SSL
	, mSSLContext(nullptr)
	, mSSLSession(nullptr)
#endif    // USE_SSL
{
	if (sSocketCount == 0)
	{
		Initialize();
	}
	sSocketCount++;

	mRefCount = new int(1);
}

#if USE_SSL
TcpSocket::TcpSocket(SOCKET socket, sockaddr_in clientInfo, SSL* pSession) : TcpSocket()
#else
TcpSocket::TcpSocket(SOCKET socket, sockaddr_in clientInfo) : TcpSocket()
#endif    // USE_SSL
{
	mSocket     = socket;
	mClientInfo = clientInfo;

#if USE_SSL
	mSSLSession = pSession;
#endif    // USE_SSL
}

TcpSocket::TcpSocket(const TcpSocket& o)
{
	mRefCount = o.mRefCount;
	(*mRefCount)++;

	sSocketCount++;

	mSocket     = o.mSocket;
	mClientInfo = o.mClientInfo;

#if USE_SSL
	mSSLContext = o.mSSLContext;
	mSSLSession = o.mSSLSession;
#endif    // USE_SSL
}

TcpSocket& TcpSocket::operator=(const TcpSocket& o)
{
	(*o.mRefCount)++;
	mRefCount = o.mRefCount;

	sSocketCount++;

	mSocket     = o.mSocket;
	mClientInfo = o.mClientInfo;

#if USE_SSL
	mSSLContext = o.mSSLContext;
	mSSLSession = o.mSSLSession;
#endif    // USE_SSL

	return *this;
}

TcpSocket::~TcpSocket()
{
	if (--(*mRefCount) == 0)
	{
		delete mRefCount;

		Close();

		sSocketCount--;
		if (sSocketCount == 0)
		{
			Shutdown();
		}
	}
}

/*-----------------------------------------------------------------------------
    Public interface
-----------------------------------------------------------------------------*/

#if USE_SSL

bool TcpSocket::InitializeSSLServer(const std::string& certFile, const std::string& keyFile)
{
	// Create context
	mSSLContext = SSL_CTX_new(TLSv1_2_server_method());
	if (!mSSLContext)
	{
		long error = ERR_get_error();
		std::cout << "TcpSocket::InitializeSSLServer : failed to create context : " << ERR_error_string(error, nullptr) << std::endl;
		return false;
	}

	// Set parameters
	SSL_CTX_set_timeout(mSSLContext, 5);

	// Load cert file
	if (SSL_CTX_use_certificate_file(mSSLContext, certFile.c_str(), SSL_FILETYPE_PEM) < 0)
	{
		long error = ERR_get_error();
		std::cout << "TcpSocket::InitializeSSLServer : failed to load cert : " << ERR_error_string(error, nullptr) << std::endl;
		return false;
	}

	// Load key file
	if (SSL_CTX_use_PrivateKey_file(mSSLContext, keyFile.c_str(), SSL_FILETYPE_PEM) < 0)
	{
		long error = ERR_get_error();
		std::cout << "TcpSocket::InitializeSSLServer : failed to load key : " << ERR_error_string(error, nullptr) << std::endl;
		return false;
	}

	return true;
}

bool TcpSocket::InitializeSSLClient(SSLVerifyMethod verifyMethod, const std::string& caCertsFile)
{
	// Create context
	mSSLContext = SSL_CTX_new(TLSv1_2_client_method());
	mSSLVerify  = verifyMethod;
	if (!mSSLContext)
	{
		long error = ERR_get_error();
		std::cout << "TcpSocket::InitializeSSLClient : failed to create context : " << ERR_error_string(error, nullptr) << std::endl;
		return false;
	}

	// Load CA certificates from a file
	if (caCertsFile.length())
	{
		if (SSL_CTX_load_verify_locations(mSSLContext, caCertsFile.c_str(), "./") < 0)
		{
			long error = ERR_get_error();
			std::cout << "TcpSocket::InitializeSSLClient : failed to load CA cert : " << ERR_error_string(error, nullptr) << std::endl;
			return false;
		}
	}

	// Load CA certificates from memory
	else if (CACertificateStore.length())
	{
		BIO* mem = BIO_new(BIO_s_mem());
		BIO_puts(mem, CACertificateStore.c_str());

		while (X509* cert = PEM_read_bio_X509(mem, NULL, 0, NULL))
		{
			X509_STORE_add_cert(SSL_CTX_get_cert_store(mSSLContext), cert);
		}

		BIO_free(mem);
	}

	// Set parameters
	SSL_CTX_set_timeout(mSSLContext, 5);
	SSL_CTX_set_verify(mSSLContext, verifyMethod == SSLVerifyMethod::FullVerification ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

	return true;
}

#endif    // USE_SSL

bool TcpSocket::Connect(const std::string& domain, uint16_t port)
{
	// Create port string
	char portString[cPortSize];
	snprintf(portString, cPortSize, "%d", port);

	// Get address info
	struct addrinfo *result, *rp;
	if (getaddrinfo(domain.c_str(), portString, &sConnectHints, &result) != 0)
	{
		std::cout << "TcpSocket::Connect : failed to get the address info : " << GetErrno() << std::endl;
		return false;
	}

	// Iterate results
	mSocket = SOCKET_ERROR;
	for (rp = result; rp != nullptr; rp = rp->ai_next)
	{
		mSocket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (mSocket == SOCKET_ERROR)
		{
			std::cout << "TcpSocket::Connect : failed to create socket : " << GetErrno() << std::endl;
			continue;
		}

		// Connect
		if (connect(mSocket, rp->ai_addr, (unsigned int) rp->ai_addrlen) != SOCKET_ERROR)
		{
			break;
		}
		else
		{
			std::cout << "TcpSocket::Connect : failed to connect : " << GetErrno() << std::endl;
		}
	}
	freeaddrinfo(result);

#if USE_SSL

	// If this is a SSL session, let's start it
	if (mSSLContext)
	{
		mSSLSession = SSL_new(mSSLContext);
		if (mSSLSession == nullptr)
		{
			std::cout << "TcpSocket::Connect : could not create a SSL session" << std::endl;
			return false;
		}
		SSL_set_fd(mSSLSession, (int) mSocket);

		// Connect
		int res = SSL_connect(mSSLSession);
		if (res != 1)
		{
			long error = ERR_get_error();
			std::cout << "TcpSocket::Connect : failed to connect : " << ERR_error_string(error, nullptr) << std::endl;

			Close();

			return false;
		}

		// Verify
		int err = SSL_get_verify_result(mSSLSession);
		if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN && mSSLVerify == SSLVerifyMethod::AcceptSelfSigned)
		{
			// Ignore error
		}
		else if (err != X509_V_OK)
		{
			std::cout << "TcpSocket::Connect : found a certificate error : " << X509_verify_cert_error_string(err) << std::endl;
			Close();
			return false;
		}

		// Get server certificate info
		X509* serverCert = SSL_get_peer_certificate(mSSLSession);
		if (serverCert == nullptr)
		{
			std::cout << "TcpSocket::Connect : no certificate on server" << std::endl;
			Close();
			return false;
		}

#if 0
		auto dumpField = [&](int field)
		{
			char commonName[512] = {0};
			X509_NAME_get_text_by_NID(X509_get_subject_name(serverCert), field, commonName, 512);
			std::cout << commonName << std::endl;
		};
		dumpField(NID_commonName);
#endif

		// Get the certificate domain name
		char commonName[512] = {0};
		X509_NAME_get_text_by_NID(X509_get_subject_name(serverCert), NID_commonName, commonName, 512);
		X509_free(serverCert);

		// Sanitize the domain name
		std::string certificateDomain(commonName);
		size_t      wildCardPosition = certificateDomain.find("*.");
		if (wildCardPosition != std::string::npos)
		{
			certificateDomain.erase(wildCardPosition, 2);
		}

		// Compare
		if (domain.find(certificateDomain) == std::string::npos)
		{
			std::cout << "TcpSocket::Connect found mismatching domain : " << commonName << std::endl;
			return false;
		}
	}

#endif    // USE_SSL

	// Check result
	return (mSocket != SOCKET_ERROR);
}

bool TcpSocket::Listen(uint16_t port, uint32_t clients)
{
	// Create port string
	char portString[cPortSize];
	snprintf(portString, cPortSize, "%d", port);

	// Get address info
	struct addrinfo *result, *rp;
	if (getaddrinfo(nullptr, portString, &sListenHints, &result) != 0)
	{
		std::cout << "TcpSocket::Listen : failed to get the address info : " << GetErrno() << std::endl;
		return false;
	}

	// Iterate results
	mSocket = SOCKET_ERROR;
	for (rp = result; rp != nullptr; rp = rp->ai_next)
	{
		int isReuse = 1;
		mSocket     = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (mSocket == SOCKET_ERROR)
		{
			std::cout << "TcpSocket::Listen : failed to create socket : " << GetErrno() << std::endl;
			continue;
		}

		// Reuse sockets
		setsockopt(mSocket, SOL_SOCKET, SO_REUSEADDR, (char*) &isReuse, sizeof(isReuse));

		// Bind
		if (bind(mSocket, rp->ai_addr, (unsigned int) rp->ai_addrlen) != SOCKET_ERROR)
		{
			break;
		}
		else
		{
			std::cout << "TcpSocket::Listen : failed to bind : " << GetErrno() << std::endl;
		}
	}
	freeaddrinfo(result);

	// Start listening
	if (mSocket == SOCKET_ERROR)
	{
		std::cout << "TcpSocket::Listen : failed to create socket : " << GetErrno() << std::endl;
		return false;
	}
	else if (listen(mSocket, clients) == SOCKET_ERROR)
	{
		std::cout << "TcpSocket::Listen : failed to listen : " << GetErrno() << std::endl;
		return false;
	}

	return true;
}

const TcpSocket TcpSocket::Accept()
{
	struct sockaddr_in clientInfo    = {0};
	socklen_t          clientInfoLen = sizeof(struct sockaddr_in);

	// Accept connection
	SOCKET clientSocket = accept(mSocket, (sockaddr*) &clientInfo, &clientInfoLen);
	if (clientSocket == INVALID_SOCKET)
	{
		std::cout << "TcpSocket::Accept : failed : " << GetErrno() << std::endl;
		clientSocket = SOCKET_ERROR;
	}

#if USE_SSL

	// Setup for SSL
	SSL* pSSLSession = nullptr;
	if (mSSLContext && clientSocket != SOCKET_ERROR)
	{
		// Create SSL session
		pSSLSession = SSL_new(mSSLContext);
		if (pSSLSession == nullptr)
		{
			std::cout << "TcpSocket::Accept : failed to create SSL session " << std::endl;
			clientSocket = SOCKET_ERROR;
		}

		// Accept the SSL session
		else
		{
			SSL_set_fd(pSSLSession, (int) clientSocket);
			if (SSL_accept(pSSLSession) <= 0)
			{
				long error = ERR_get_error();
				std::cout << "TcpSocket::Accept : failed to establish secure session : " << ERR_error_string(error, nullptr) << std::endl;

				clientSocket = SOCKET_ERROR;
				SSL_free(pSSLSession);
				pSSLSession = nullptr;
			}
		}
	}

	// Create a new socket instance to store the data
	return TcpSocket(clientSocket, clientInfo, pSSLSession);

#else

	// Create a new socket instance to store the data
	return TcpSocket(clientSocket, clientInfo);

#endif    // USE_SSL
}

bool TcpSocket::IsValid() const
{
	return (mSocket != SOCKET_ERROR);
}

bool TcpSocket::Write(const std::string& data)
{
#if USE_SSL
	if (mSSLSession)
	{
		int length = SSL_write(mSSLSession, data.data(), (int) data.size());
		return (length == data.size());
	}
	else
#endif    // USE_SSL

	{

		int length = send(mSocket, (const char*) (data.data()), (int) data.size(), 0);
		return (length == data.size());
	}
}

bool TcpSocket::Read(std::string& data)
{
	uint8_t buffer[cBufferSize];
	int     length;

	// Read data from socket
#if USE_SSL
	if (mSSLSession)
	{
		length = SSL_read(mSSLSession, (char*) (buffer), cBufferSize - 1);
	}
	else
#endif    // USE_SSL
	{
		length = recv(mSocket, (char*) (buffer), cBufferSize - 1, 0);
	}

	// Verify read
	if (length >= 0 && length < cBufferSize - 1)
	{
		buffer[length] = '\0';
		data.assign(buffer, buffer + length);
		return true;
	}
	else
	{
		return false;
	}
}

std::string TcpSocket::GetClientAddress() const
{
	char address[16] = {0};

	snprintf(address, 16, "%d.%d.%d.%d", int(mClientInfo.sin_addr.s_addr & 0xFF), int((mClientInfo.sin_addr.s_addr & 0xFF00) >> 8),
		int((mClientInfo.sin_addr.s_addr & 0xFF0000) >> 16), int((mClientInfo.sin_addr.s_addr & 0xFF000000) >> 24));

	return std::string(address);
}

void TcpSocket::Close()
{
	// Shutdown socket
	if (mSocket != SOCKET_ERROR)
	{
#ifdef WIN32
		shutdown(mSocket, SD_BOTH);
#else
		shutdown(mSocket, SHUT_RDWR);
#endif
		closesocket(mSocket);
		mSocket = SOCKET_ERROR;
	}

#if USE_SSL

	// Shutdown SSL session
	if (mSSLSession)
	{
		SSL_shutdown(mSSLSession);
		SSL_free(mSSLSession);
		mSSLSession = nullptr;
	}

	// Shutdown SSL context
	if (mSSLContext)
	{
		SSL_CTX_free(mSSLContext);
		mSSLContext = nullptr;
	}
#endif    // USE_SSL
}

/*-----------------------------------------------------------------------------
    Static interface
-----------------------------------------------------------------------------*/

int             TcpSocket::sSocketCount  = 0;
struct addrinfo TcpSocket::sConnectHints = {0};
struct addrinfo TcpSocket::sListenHints  = {0};

void TcpSocket::Initialize()
{
#ifdef WIN32
	WSADATA wsa;
	int     err = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (err < 0)
	{
		exit(EXIT_FAILURE);
	}
#endif

#if USE_SSL
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#endif    // USE_SSL

	sConnectHints.ai_family   = AF_INET;
	sConnectHints.ai_socktype = SOCK_STREAM;
	sConnectHints.ai_flags    = 0;
	sConnectHints.ai_protocol = 0;

	sListenHints.ai_family   = AF_INET;
	sListenHints.ai_socktype = SOCK_STREAM;
	sListenHints.ai_flags    = AI_PASSIVE;
	sListenHints.ai_protocol = 0;
}

void TcpSocket::Shutdown()
{
#ifdef WIN32
	WSACleanup();
#endif

#if USE_SSL
	EVP_cleanup();
#endif    // USE_SSL
}

int TcpSocket::GetErrno()
{
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}
