package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type HarfangLabDetection struct{}

func (w *HarfangLabDetection) Name() string {
	return "HarfangLab"
}

func (w *HarfangLabDetection) Type() resources.EDRType {
	return resources.HarfangLabEDR
}

var HarfangLabHeuristic = []string{
	"HarfangLab\\",
	"C:\\Program Files\\HarfangLab",
	"C:\\Program Files\\HarfangLab\\drivers",
	"hurukai",
	"hurukai-av-update.dll",
	"hldevicecontrol.sys",
	"hurukai-av",
	"hurukai-ui",
	"hurukai-av.exe",
	"hurukai-ui.exe",
	"hurukai-av.dll",
	"hlelam.sys",
	"hlprotect.sys",
}

func (w *HarfangLabDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(HarfangLabHeuristic)
	if !ok {
		return "", false
	}

	return resources.SentinelOneEDR, true
}
