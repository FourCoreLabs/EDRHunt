package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type TrendMicroDetection struct{}

func (w *TrendMicroDetection) Name() string {
	return "Trend Micro Deep Security"
}

func (w *TrendMicroDetection) Type() resources.EDRType {
	return resources.TrendMicroEDR
}

var TrendMicroHeuristic = []string{
	"Deep Security Agent\\",
	"dsa",
	"Notifier",
	"Trend Micro",
	"ntrmv.exe",
	"pccntmon.exe",
	"AosUImanager.exe",
	"NTRTScan.exe",
	"AddinSentry.exe ",
	"tmaseng.dll",
	"TMAS_OL.exe",
	"TMAS_OLA.dll",
	"TMAS_OLImp.exe",
	"TMAS_OLShare.dll",
	"EMapiWpr.dll",
	"TMAS_OLSentry.exe",
	"ufnavi.exe",
	"Clnrbin.exe",
	"vizorhtmldialog.exe",
	"pwmConsole.exe",
	"PwmSvc.exe",
	"coreServiceShell.exe",
	"ds_agent.exe",
	"ufnavi.exe",
	"SfCtlCom.exe",
}

func (w *TrendMicroDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TrendMicroHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}
