package resources

type EDRDetection interface {
	Detect(data SystemData) (EDRType, bool)
	Name() string
	Type() EDRType
}

type EDRType string

var (
	WinDefenderEDR EDRType = "defender"
	KaskperskyEDR  EDRType = "kaspersky"
	CrowdstrikeEDR EDRType = "crowdstrike"
	McafeeEDR      EDRType = "mcafee"
	SymantecEDR    EDRType = "symantec"
	CylanceEDR     EDRType = "cylance"
	CarbonBlackEDR EDRType = "carbon_black"
	SentinelOneEDR EDRType = "sentinel_one"
	FireEyeEDR     EDRType = "fireeye"
)
