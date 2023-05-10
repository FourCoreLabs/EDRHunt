package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type QualysDetection struct{}

func (w *QualysDetection) Name() string {
	return "Qualys Cloud Agent EDR"
}

func (w *QualysDetection) Type() resources.EDRType {
	return resources.QualysEDR
}

var QualysHeuristic = []string{
	"Qualys",
	"qualysagent.exe",
	"QualysProxy.exe",
	"QualysAgentUI.exe",
}

func (w *QualysDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(QualysHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}
