package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

var (
	Scanners = []resources.EDRDetection{
		&CarbonBlackDetection{},
		&CrowdstrikeDetection{},
		&CylanceDetection{},
		&FireEyeDetection{},
		&HarfangLabDetection{},
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
		&LimacharlieDetection{},
	}
)
