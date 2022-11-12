package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type McafeeDetection struct{}

func (w *McafeeDetection) Name() string {
	return "McAfee MVISION Endpoint Detection and Response"
}

func (w *McafeeDetection) Type() resources.EDRType {
	return resources.McafeeEDR
}

var McafeeHeuristic = []string{
	"Mcafee",
	"mcupdate.exe",
	"McAfeeAgent",
	"MfeServiceMgr.exe ",
	"McAPExe.exe",
	"mfeffcoreservice.exe",
	"MfeEpeSvc.exe",
}

func (w *McafeeDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(McafeeHeuristic)
	if !ok {
		return "", false
	}

	return resources.McafeeEDR, true
}
