package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type CheckPointDetection struct{}

func (w *CheckPointDetection) Name() string {
	return "Carbon Black"
}

func (w *CheckPointDetection) Type() resources.EDRType {
	return resources.CheckPointEDR
}

var CheckPointHeuristic = []string{
	"Checkpoint",
	"tracsrvwrapper.exe",
	"C:\\Program Files\\checkpoint\\endpoint connect\\tracsrvwrapper.exe",
	"TrGUI.exe",
	"TracCAPI.exe",
	"dtplat.dll",
	"epcgina.dll",
	"epcgina_user64.dll",
	"LogonISReg.dll",
	"OsMonitor.dll",
	"ProcessMonitor.dll",
	"proxystub.dll",
	"ScriptRun.dll",
	"SCVMonitor.dll",
	"scvprod_lang_pack.dll",
	"SCUIAPI.dll",
	"cpmsi_tool.exe",
	"DataStruct.dll",
	"FileHash_DYN.dll",
	"trac.exe",
	"TrAPI.dll",
	"vna_coinstall.dll - vna",
	"vna_install64.exe",
	"vna_utils.exe",
	"TracSrvWrapper.exe",
	"TrGUI.exe",
	"TracSrvWrapper.exe",
	"vsmon.exe",
	"C:\\Program Files\\CheckPoint\\ZoneAlarm\\vsmon.exe",
	"TrueVector",
	"p95tray.exe",
}

func (w *CheckPointDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(CheckPointHeuristic)
	if !ok {
		return "", false
	}

	return resources.CheckPointEDR, true
}
