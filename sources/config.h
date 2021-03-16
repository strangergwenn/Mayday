#include "tcpsocket.h"

// Domain and project settings
constexpr auto MaydayReportDomain = "unrealengine.com";             // Domain name
constexpr auto MaydayReportURL    = "/mayday-crash-reports.php";    // Relative URL
constexpr auto MaydayUserAgent    = "MayDay";                       // HTTP user-agent string
constexpr auto MaydayProjectName  = "ProjectName";                  // Unreal Engine project name
constexpr auto MaydayGameName     = "Project Name";                 // Full game name

// Behavior settings
constexpr bool MaydayUseHTTPS = true;
constexpr auto MaydayVerifyMethod =
	TcpSocket::SSLVerifyMethod::AcceptSelfSigned;    // FullVerification, DomainAndCertificate, AcceptSelfSigned
