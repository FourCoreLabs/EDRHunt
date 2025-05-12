package resources

type EDRDetection interface {
	Detect(data SystemData) (EDRType, bool)
	Name() string
	Type() EDRType
}

type EDRType string

var (
	WinDefenderEDR  EDRType = "defender"
	KaskperskyEDR   EDRType = "kaspersky"
	CrowdstrikeEDR  EDRType = "crowdstrike"
	McafeeEDR       EDRType = "mcafee"
	SymantecEDR     EDRType = "symantec"
	CylanceEDR      EDRType = "cylance"
	CarbonBlackEDR  EDRType = "carbon_black"
	SentinelOneEDR  EDRType = "sentinel_one"
	FireEyeEDR      EDRType = "fireeye"
	ElasticAgentEDR EDRType = "elastic_agent"
	QualysEDR       EDRType = "qualys"
	TrendMicroEDR   EDRType = "trend_micro"
	ESETEDR         EDRType = "eset"
	CybereasonEDR   EDRType = "cybereason"
	BitDefenderEDR  EDRType = "bitdefender"
	CheckPointEDR   EDRType = "checkpoint"
	CynetEDR        EDRType = "cynet"
	DeepInstinctEDR EDRType = "deepinstinct"
	SophosEDR       EDRType = "sophos"
	FortinetEDR     EDRType = "fortinet"
	MalwareBytesEDR EDRType = "malwarebytes"
	LimacharlieEDR  EDRType = "limacharlie"
	HarfangLabEDR   EDRType = "harfanglab"
)
