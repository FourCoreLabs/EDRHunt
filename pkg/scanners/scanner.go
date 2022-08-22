package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

var (
	Scanners = []resources.EDRDetection{
		&CarbonBlackDetection{},
		&CrowdstrikeDetection{},
		&CylanceDetection{},
		&FireEyeDetection{},
		&KaskperskyDetection{},
		&McafeeDetection{},
		&SymantecDetection{},
		&SentinelOneDetection{},
		&WinDefenderDetection{},
		&ElasticAgentDetection{},
		&ESETEDRDetection{},
		&QualysDetection{},
		&TrendMicroDetection{},
		&CybereasonDetection{},
		&BitDefenderDetection{},
		&CheckPointDetection{},
		&CynetDetection{},
		&DeepInstictDetection{},
		&SophosDetection{},
		&FortinetDetection{},
		&MalwareBytesDetection{},
	}
)
