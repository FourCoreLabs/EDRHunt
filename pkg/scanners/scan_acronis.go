package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type AcronisDetection struct{}

func (w *AcronisDetection) Name() string {
	return "Acronis Cyber Protect"
}

func (w *AcronisDetection) Type() resources.EDRType {
	return resources.AcronisEDR
}

var AcronisHeuristic = []string{
	"cyber-protect-service.exe",
	"aakore.exe",
	"AcronisCyberProtectionService",
	"AcronisActiveProtectionService",
	"C:\\Program Files\\Acronis",
}

func (w *AcronisDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(AcronisHeuristic)
	if !ok {
		return "", false
	}

	return resources.AcronisEDR, true
}
