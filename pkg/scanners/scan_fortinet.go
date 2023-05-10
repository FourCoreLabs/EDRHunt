package scanners

import "github.com/fourcorelabs/edrhunt/pkg/resources"

type FortinetDetection struct{}

func (w *FortinetDetection) Name() string {
	return "Fortinet"
}

func (w *FortinetDetection) Type() resources.EDRType {
	return resources.FortinetEDR
}

var FortinetHeuristic = []string{
	"Fortinet",
	"dcagent_amd64.dll",
	"FSAEConfig.exe",
	"fortilspheuristics.dll",
	"fccomintdll.dll",
	"fcoeam.dll",
	"fccomint.exe",
	"fclanguageselector.exe",
	"fortifw.exe",
	"fortitray.exe",
	"libcfg.dll",
	"fcappdb.exe",
	"fcoehook.dll",
	"fcwizard.exe",
	"fcresc.dll",
	"fortiwf.exe",
	"forticlish.dll",
	"fortiece.dll",
	"libavr.dll",
	"fortiwadbd.exe",
	"fcdblog.exe",
	"fortiwad.exe",
	"fortiproxy.exe",
	"fortiskin.dll",
	"fortiscand.exe",
	"fortivpnst.dll",
	"fortivpnst.exe",
	"fortivpnst64.dll",
	"fasle.dll",
	"fcwscd7.exe",
	"forticlient.exe",
	"forticlish.dll",
	"FortiClient Service Scheduler",
	"FortiClient.exe",
	"fortiwad.exe",
	"fortiproxy.exe",
	"FortiLSPHeuristics.dll",
	"npccpluginex.dll",
	"nptcplugin.dll",
	"npccplugin.dll",
	"FCCOMIntDLL.dll",
	"FCOEAM.dll",
	"FSSOMA.exe",
	"LaunchCacheClean.dll",
	"launchcacheclean64.dll",
	"FCCOMInt.exe",
	"FCVbltScan.exe",
	"sslvpnhostcheck.dll",
	"sslvpnhostcheck64.dll",
	"FortiESNAC.exe",
	"FortiTray.exe",
	"FCConfig.exe",
	"FCOEHook.dll",
	"FCResc.dll",
	"forticachecleaner.dll",
	"FortiCacheCleaner64.dll",
	"forticredentialprovider.dll",
	"FortiCredentialProvider2x64.dll",
	"forticredentialprovider64.dll",
	"FortiTrayResc.dll",
	"FortiWF.exe",
	"EPCUserAvatar.exe",
	"FortiAvatar.exe",
	"FortiCliSh.dll",
	"FortiCliSh64.dll",
	"fortifws.exe",
	"FortiWadbd.exe",
	"FortiClient_Diagnostic_Tool.exe",
	"forticontrol.dll",
	"FortiSSLVPNdaemon.exe",
	"FortiCliSh.dll",
	"FortiCliSh64.dll",
	"npccpluginex.dll",
	"nptcplugin.dll",
	"npccplugin.dll",
	"FortiClient Service Scheduler",
	"FortiESNAC.exe",
	"FortiWad.exe",
	"FortiProxy.exe",
}

func (w *FortinetDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(FortinetHeuristic)
	if !ok {
		return "", false
	}

	return resources.FortinetEDR, true
}
