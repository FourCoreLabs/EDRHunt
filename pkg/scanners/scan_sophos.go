package scanners

import "github.com/FourCoreLabs/EDRHunt/pkg/resources"

type SophosDetection struct{}

func (w *SophosDetection) Name() string {
	return "Sophos"
}

func (w *SophosDetection) Type() resources.EDRType {
	return resources.SophosEDR
}

var SophosHeuristic = []string{
	"Sophos",
	"SVRTgui.exe",
	"SVRTcli.exe",
	"Sophos Virus Removal Tool install.exe",
	"SVRTcli.exe",
	"SVRTgui.exe",
	"SCTCleanupService.exe",
	"SVRTservice.exe",
	"osdp.dll",
	"SAVI.dll",
	"veex.dll",
	"rkdisk.dll",
	"SCTBootTasks.exe",
	"SUMService.exe",
	"SVRTservice.exe",
	"SCFService.exe",
	"SCFManager.exe",
	"SpaRmsAdapter.dll",
	"sargui.exe",
	"Sophos Computer Security Scan.exe",
	"sntpservice.exe",
	"SophosLinkIconHandler32.dll",
	"McsHeartbeat.exe",
	"SAVAdminService.exe",
	"conan.dll",
	"DCManagement.dll",
	"DesktopMessaging.dll",
	"DetectionFeedback.dll",
	"DeviceControlPlugin.dll",
	"DriveProcessor.dll",
	"EEConsumer.dll",
	"ForceUpdateAlongSideSGN.exe",
	"FSDecomposer.dll",
	"ICAdapter.dll",
	"ICManagement.dll",
	"ICProcessors.dll",
	"osdp.dll",
	"SavAdapter.dll",
	"SAVAdminService.exe",
	"SAVCleanupService.exe",
	"SAVControl.dll",
	"SAVI.dll",
	"SavMain.exe",
	"savmscm.dll",
	"SavNeutralRes.dll",
	"SavPlugin.dll",
	"SavProgress.exe",
	"SavProxy.exe",
	"SavRes.dll",
	"SavResChs.dll",
	"SavResCht.dll",
	"SavResDeu.dll",
	"SavResEng.dll",
	"SavResEsp.dll",
	"SavSecurity.dll",
	"SavService.exe",
	"SavShellExt.dll",
	"SavShellExtX64.dll",
	"bpaif.dll",
	"swc_service.exe",
	"swcadapter.dll",
	"swi_callout.sys",
	"swi_service.exe",
	"swc_service.exe",
	"swi_filter.exe",
	"SophosUpdate.exe",
	"ALMsg.dll",
	"ALUpdate.exe",
	"AUAdapter.dll",
	"ChannelUpdater.dll",
	"cidsync.dll",
	"config.dll",
	"crypto.dll",
	"EECustomActions.dll",
	"InstlMgr.dll",
	"ispsheet.dll",
	"SAUConfigDLL.dll",
	"SingleGUIPlugin.dll",
	"SophosAlert.exe",
	"swlocale.dll",
	"SavShellExt.dll",
	"SavShellExtX64.dll",
	"SavMain.exe",
	"SAVAdminService.exe",
	"SAVCleanupService.exe",
	"SavService.exe",
}

func (w *SophosDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SophosHeuristic)
	if !ok {
		return "", false
	}

	return resources.SophosEDR, true
}
