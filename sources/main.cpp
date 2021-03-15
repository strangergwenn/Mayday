#include "tcpsocket.h"
#include "certs.h"

#include <iostream>

class HttpRequest : TcpSocket
{
public:
	HttpRequest(const std::string& domain, const std::string& page, const std::string& caMemory)
	{
		InitializeSSLClient("", caMemory, false);

		if (Connect(domain, 443))
		{
			std::cout << "HttpSocket::HttpSocket : connected" << std::endl;

#if 1

			std::string content =
				"dryrun=1&game=Nova&expression=Trajectory.IsValid%28%29%20%26%26%20false&function=SNovaTrajectoryCalculator::"
				"SimulateTrajectories&file=D:\\Nova\\Source\\Nova\\UI\\Component\\NovaTrajectoryCalculator.cpp&callstack="
				"ThisIsACallstack";

			std::string headers = "POST https://" + domain + page + " HTTP/1.0\r\nHost: " + domain +
								  "\r\nUser-Agent: DeimosGames\r\nContent-Length: " + std::to_string(content.size()) +
								  "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";
#else

			std::string headers = "GET https://" + domain + page + " HTTP/1.0\r\nHost: " + domain +
								  "\r\nUser-Agent: DeimosGames\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";

			std::string content = "";

#endif

			std::cout << headers + content << std::endl;

			if (Write(headers + content))
			{
				std::cout << "HttpSocket::HttpSocket : sent data" << std::endl;

				std::string result;
				if (Read(result))
				{
					std::cout << result << std::endl;
				}
			}
		}
	}

	~HttpRequest()
	{
		Close();
	}
};

int main(int argc, char** argv)
{
	HttpRequest socket("deimosgaxw.cluster020.hosting.ovh.net", "/deimosgames/report.php", DSTRootX3);
	// HttpRequest socket("www.google.com", "/", GlobalSign);
	// HttpRequest socket("arstechnica.com", "/", AmazonRootCA1);

	return EXIT_SUCCESS;
}
