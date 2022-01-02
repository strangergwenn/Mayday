/**
 * 'Mayday' crash reporter for Unreal Engine games
 * Check config.h for setting up the reporter for your game !
 * Gwennaël Arbona - 2022 - Deimos Games
 */

#include "tcpsocket.h"
#include "config.h"

#include "zlib.h"

#include <chrono>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <sstream>

/** Basic HTTP request class **/
class HttpRequest : TcpSocket
{
public:
	HttpRequest(const std::string& domain, const std::string& page, bool useSSL = true) : mDomain(domain), mPage(page), mUseSSL(useSSL)
	{
		if (mUseSSL)
		{
			InitializeSSLClient(MaydayVerifyMethod);
		}

		if (!Connect(domain, mUseSSL ? 443 : 80))
		{
			std::cout << "HttpRequest::HttpSocket : failed to connect" << std::endl;
		}
	}

	static std::string FormatHeaders(const std::string& domain, const std::string& page, size_t contentSize, bool useSSL, bool usePOST)
	{
		std::string headers;

		headers += std::string(usePOST ? "POST" : "GET") + " ";
		headers += std::string(useSSL ? "https" : "http") + "://";
		headers += domain + page + " HTTP/1.0\r\n";
		headers += "Host: " + domain + "\r\n";
		headers += "User-Agent: " + std::string(MaydayUserAgent) + "\r\n";
		headers += "Content-Length: " + std::to_string(contentSize) + "\r\n";
		headers += "Content-Type: application/x-www-form-urlencoded\r\n\r\n";

		return headers;
	}

	void Send(const std::string& content = "", bool usePOST = false)
	{
		std::string headers = FormatHeaders(mDomain, mPage, content.length(), mUseSSL, usePOST);

		if (!Write(headers + content))
		{
			std::cout << "HttpRequest::HttpSocket : failed to send data" << std::endl;
		}
	}

	std::string Receive()
	{
		std::string result;
		Read(result);
		return result;
	}

private:
	std::string mDomain;
	std::string mPage;
	bool        mUseSSL;
};

/** Main application code */
int main(int argc, char** argv)
{
	const std::string minidumpName     = "UEMinidump.dmp";
	const std::string crashContextName = "CrashContext.runtime-xml";

#if WIN32
	const std::string sep         = "\\";
	const std::string appDataPath = std::getenv("LOCALAPPDATA");
	const std::string configDir   = "Windows";
#else
	const std::string sep         = "/";
	const std::string appDataPath = "~/.config/Epic";
	const std::string configDir   = "Linux";
#endif

	/** Get the UNIX timestamp of a given file path */
	auto getCreationTimestamp = [](const std::string& f)
	{
		std::filesystem::file_time_type ftime        = std::filesystem::last_write_time(f);
		std::chrono::time_point         timePoint    = std::filesystem::file_time_type::clock::time_point(ftime);
		std::chrono::seconds            secondsEpoch = std::chrono::time_point_cast<std::chrono::seconds>(timePoint).time_since_epoch();
		std::chrono::seconds            secondsValue = std::chrono::duration_cast<std::chrono::seconds>(secondsEpoch);

		return secondsValue.count();
	};

	/** Get the most recently created crash report directory in the base directory */
	auto getMostRecentCrashReport = [&](const std::string& crashReportDirectory)
	{
		long long   highestCreationTimestamp = 0;
		std::string mostRecentCrashReport;
		for (auto& p : std::filesystem::directory_iterator(crashReportDirectory))
		{
			const std::string& file              = p.path().string() + sep + minidumpName;
			long long          creationTimestamp = getCreationTimestamp(file);

			if (creationTimestamp > highestCreationTimestamp)
			{
				highestCreationTimestamp = creationTimestamp;
				mostRecentCrashReport    = p.path().string();
			}
		}

		return mostRecentCrashReport;
	};

	/** Confirm whether the user accepts crash reports by reading EnableCrashReports in game user settings **/
	auto isCrashReportEnabled = [](const std::string& configFilePath)
	{
		std::ifstream file(configFilePath);
		if (file)
		{
			std::string line;
			while (std::getline(file, line))
			{
				std::istringstream lineStream(line);
				std::string        key;
				if (std::getline(lineStream, key, '='))
				{
					if (key == "EnableCrashReports")
					{
						std::string value;
						std::getline(lineStream, value);

						bool isAllowed = (value == "True" || value == "true" || value == "1" || value == "Yes" || value == "yes");
						if (!isAllowed)
						{
							std::cout << "Crash reporting was disabled by the user and will not run." << std::endl;
						}

						return isAllowed;
					}
				}
			}
		}

		// The default is to allow crash reports, not because it should be the default, but because a game might not implement
		// EnableCrashReports at all. The actual default behavior will depend on a developer's implementation of EnableCrashReports.
		return true;
	};

	/** Compress a buffer using Zlib */
	auto compressBuffer = [](char* pBuffer, size_t length)
	{
		std::vector<unsigned char> output;
		output.resize(length);

		uLongf size = (uLongf) length;
		compress(output.data(), &size, (const Bytef*) pBuffer, (uLong) length);
		output.resize(size);

		return output;
	};

	/** Encode binary data as base64*/
	auto base64 = [](const std::vector<unsigned char>& in)
	{
		static constexpr char* base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		size_t      resultLength = 4 * ((in.size() + 2) / 3);
		std::string result(resultLength, 0);

		for (int i = 0, j = 0; i < in.size();)
		{
			uint32_t octet_a = i < in.size() ? (unsigned char) in.data()[i++] : 0;
			uint32_t octet_b = i < in.size() ? (unsigned char) in.data()[i++] : 0;
			uint32_t octet_c = i < in.size() ? (unsigned char) in.data()[i++] : 0;

			uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

			result[j++] = base[(triple >> 3 * 6) & 0x3F];
			result[j++] = base[(triple >> 2 * 6) & 0x3F];
			result[j++] = base[(triple >> 1 * 6) & 0x3F];
			result[j++] = base[(triple >> 0 * 6) & 0x3F];
		}

		return result;
	};

	/** Replace all occurrences of match with replace in str */
	auto findAndReplaceAll = [](std::string& str, const std::string& match, const std::string& replace)
	{
		size_t pos = str.find(match);
		while (pos != std::string::npos)
		{
			str.replace(pos, match.size(), replace);
			pos = str.find(match, pos + replace.size());
		}
	};

	/** Read a crash report file, compress it with Zlib, and return it as a base64 string */
	auto readCompressEncodeFile = [&](const std::string& filePath)
	{
		std::string   result;
		std::ifstream file(filePath, std::ifstream::binary);

		if (file)
		{
			// Get file length
			file.seekg(0, file.end);
			std::streampos length = file.tellg();
			file.seekg(0, file.beg);
			std::vector<char> buffer;
			buffer.resize(length);

			// Read the file
			file.read(buffer.data(), buffer.size());
			if (file)
			{
				// Compress, encode and escape the dump file
				result = base64(compressBuffer(buffer.data(), buffer.size()));
				findAndReplaceAll(result, "+", "%2B");
			}
		}

		std::cout << "Read " + filePath + " into " + std::to_string(result.length()) + " bytes" << std::endl;
		return result;
	};

	// Run the crash reporter if enabled
	const std::string savedDir             = appDataPath + sep + MaydayProjectName + sep + "Saved" + sep;
	const std::string configFile           = savedDir + "Config" + sep + configDir + sep + "GameUserSettings.ini";
	const std::string crashReportDirectory = savedDir + "Crashes" + sep;
	if (isCrashReportEnabled(configFile))
	{
		// Read and compress the files
		const std::string mostRecentCrashReport  = getMostRecentCrashReport(crashReportDirectory);
		const std::string compressedMinidump     = readCompressEncodeFile(mostRecentCrashReport + sep + minidumpName);
		const std::string compressedCrashContext = readCompressEncodeFile(mostRecentCrashReport + sep + crashContextName);

		// Format the content
		std::string content;
		content += "game=" + std::string(MaydayGameName);
		content += "&minidump=" + compressedMinidump;
		content += "&context=" + compressedCrashContext;

		// Send the report
		HttpRequest request(MaydayReportDomain, MaydayReportURL, MaydayUseHTTPS);
		request.Send(content, true);
		std::cout << "Report was sent, awaiting response..." << std::endl;
		std::cout << request.Receive() << std::endl;
	}

	return EXIT_SUCCESS;
}
