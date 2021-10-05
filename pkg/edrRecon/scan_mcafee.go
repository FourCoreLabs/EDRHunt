package edrRecon

type McafeeDetection struct{}

func (w *McafeeDetection) Name() string {
	return "McAfee MVISION Endpoint Detection and Response"
}

func (w *McafeeDetection) Type() EDRType {
	return McafeeEDR
}

var McafeeHeuristic = []string{
	"Mcafee\\",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
}

func (w *McafeeDetection) Detect(data SystemData) (EDRType, bool) {
	_, ok := data.CountMatchesAll(McafeeHeuristic)
	if !ok {
		return "", false
	}

	return McafeeEDR, true
}
