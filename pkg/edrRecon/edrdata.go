package edrRecon

// var (
// 	EdrList            = []string{}
// 	RegistryReconList  = []string{}
// 	RegistrySearchList = []string{}
// 	key                = []byte("obscurityisablessing")
// )

// var obfEdrList = []string{
// 	"0e01070a03170a1b171a1c0d07",
// 	"0e0f000a5b160518",
// 	"0e0c070a551f08180e080104",
// 	"0e0c070a581f08180e080104",
// 	"0e0c070a18130503181b16",
// 	"0e0c070a550400060c1a",
// 	"0e0c070a580400060c1a",
// 	"0e0c070a031b1b010a",
// 	"0e120310101c1a11",
// 	"0e17070b011319",
// 	"0e14121001",
// 	"0e141600011d",
// 	"0c031d02070b",
// 	"0c0301011a1c0b18180a18",
// 	"0c0301011a1c49161508100a",
// 	"0c005d060d17",
// 	"0c0b00001a130404",
// 	"0c0b00001a52081909",
// 	"0c0d060d01171b171c1907",
// 	"0c0d060d01171b00180a18",
// 	"0c10120e0100080d",
// 	"0c1000100311",
// 	"0c101c1411011d06100216",
// 	"0c111204101c1d",
// 	"0c1115021911061a",
// 	"0c11000b101e05",
// 	"0c1b1106071708071607",
// 	"0c1b100f1a00081918",
// 	"0c1b1f021b110c",
// 	"0c1b1c13011b0a07",
// 	"0c1b061311131d11",
// 	"0c1b05060713",
// 	"0c1b000607040c06",
// 	"0c1b0711140b",
// 	"0b030108010008171c",
// 	"0b0715061b16191b100707",
// 	"0b0715061b160c06",
// 	"0a071017071e",
// 	"0a0e1210011b0a",
// 	"0a0c1704141f0c",
// 	"094f000616071b11",
// 	"090d01001002061d171d",
// 	"090b0106100b0c",
// 	"08101c161b16051d170e",
// 	"2830211010001f1d1a",
// 	"060c001310111d1b0b",
// 	"0614120d011b",
// 	"0403001310001a1f00",
// 	"030310161b13",
// 	"030d14111d0b1d1c14",
// 	"02031f1414000c",
// 	"02031d071c130700",
// 	"020112051017",
// 	"020d01131d1b1a111a",
// 	"0211121016070018",
// 	"02111e13101c0e",
// 	"010b00100704",
// 	"000f1d0a",
// 	"000f1d0a14150c1a0d",
// 	"00110216100010",
// 	"3f031f0c5533050016493d04161b0a01181a",
// 	"1f0516131a010c060f001004",
// 	"1f05001a06060c190d1b1218",
// 	"1f101a151c1e0c131c0e06001008",
// 	"1f101c0002130518",
// 	"1f101c1710111d1b0b1a1613140506",
// 	"1e1012071400",
// 	"1d071700191d081f",
// 	"1c07101607171e1b0b0200",
// 	"1c071016071b1d0d110c120d16041616011f07040a",
// 	"1c071e0f14070717111a05",
// 	"1c071d171c1c0c18",
// 	"1c07030f1c040c01090d1215",
// 	"1c0b000a11011a110b1f1a0207",
// 	"1c0b000a05011a110b1f1a0207",
// 	"1c0b000a05011c001005",
// 	"1c0f104d100a0c",
// 	"1c0f1004001b",
// 	"1c0c12004346",
// 	"1c0d030b1a01",
// 	"1c121f161b19",
// 	"1c10071005",
// 	"1c1b1e021b060c17",
// 	"1c1b1e001a001901",
// 	"1c1b1e0613131a1d",
// 	"1c1b000a1b060c0617081f",
// 	"1c1b000e1a1c",
// 	"1b031d0a001f",
// 	"1b06124d100a0c",
// 	"1b0612141a0002",
// 	"1b120a171d1d07",
// 	"190710170713",
// 	"180b1d001a1e05111a1d",
// 	"180b1d071a051a071c07000e10",
// 	"180b0106061a080612",
// 	"1b0a01061406",
// 	"170314175b171111",
// 	"170314171b1d1d1d1f47161907",
// }

// var obfRegistryReconList = []string{
// 	"3c071d171c1c0c18592512031130",
// 	"3c071d171c1c0c18592814040c1839",
// 	"0a1a0706071c0818302d",
// 	"290b0106300b0c",
// 	"2c1b1f021b110c28",
// 	"2c1b1f021b110c44",
// 	"2c1b1f021b110c45",
// 	"2c1b1f021b110c46",
// 	"2c101c1411211d061002163d",
// 	"4a312a3021372426362627443e1f1c00070c03545d3e17111c040c060a3510130d1b0100071b070c0a3e301031171f1d1a0c300e0c18171c1f47070909",
// 	"4a312a3021372426362627443e1f1c00070c03545d3e17111c040c060a3510130d1b0100071b070c0a3e3010331b1b190e0801042302041f0a1a0714410b1d05",
// 	"22011205101735",
// 	"22013205101728131c07073d",
// 	"2e32230c191b0a0d37081e04",
// 	"2a32230c191b0a0d37081e04",
// 	"202320331a1e00170027120c07",
// 	"3c1b1e021b060c17",
// 	"3c1b1e021b060c17592c1d0512030c1d07493e1500161600011b061a25",
// 	"380b1d071a051a543d0c15040c080001",
// 	"2b1212271c010816150c17",
// 	"2b0b0002171e0c261c081f350b01003e1c07071300101a0d12",
// 	"2c0301011a1c2b18180a183d",
// 	"2c003706131707071c35",
// 	"3c071d101a003f110b1a1a0e0c",
// }

// var obfRegistrySearchList = []string{
// 	"1d07144304070c06004951292920282f20303d332a2f2f2000001b11171d300e0c18171c1f3a0b1333311611031b0a110a3527021205152f23081c060207070607014b",
// 	"1d07144304070c06004951292920282f3b283c233823212629362c273a3b3a3136252a3d2f3a17141b071e3f373b26275b",
// 	"1d07144304070c0600493b2a2e2139203c2f3a302e30363f381b0a06161a1c071630321a1d0d01101c3e301607000c1a0d3f161311050a1d2f3c000e01110702191e",
// 	"1d07144304070c0600493b2a2e2139203c2f3a302e30363f381b0a06161a1c071630321a1d0d01101c3e301607000c1a0d3f161311050a1d2f39010b06011a06062e3a0d0a1d160c",
// 	"1d07144304070c060049512929293c2c3f262d26233d3e22363a203a3c3520383138203e2f2a1b151d071d17361d07000b061f32071839301c071a15000e2f2f26334b",
// 	"1d07144304070c06004951292920282f200608131803010629220618100a1a041130281a101b01140004073f221b0710161e003d2609131a100c29120e101741",
// 	"1d07144304070c060049512929293c2c3f262d26233d3e22363a203a3c35202e24383232212c322a0601010c061d0f00253e1a0f06031200532d0b010a0c1706072e3b1118055e350b010053231b01130a01070a1a1c4b",
// 	"1d07144304070c060049512929293c2c3f262d26233d3e22363a203a3c35202e24383232212c322a0601010c061d0f00253e1a0f0603120053280a110e0c100611523d1c0b0c1215423c171c070c0d13060d1d3f260608000c1a51",
// 	"1d07144304070c0600493b2a2e2139201c0f1a100e10163f381128121c0c2f240c08151c1a071a3b2e34",
// 	"1d07144304070c0600493b2a2e2139201c0f1a100e10163f260b0415171d1602",
// 	"1d07144304070c0600493b2a2e2139201c0f1a100e10163f360b0515170a163d2609161807061e",
// 	"1d07144304070c0600493b2a2e2139201c0f1a100e10163f36102d111f0c1d1207",
// 	"1d07144304070c0600493b2a2e2139201c0f1a100e10163f360006031d3a07130b07002f3a0708230d",
// 	"1d07144304070c06004951292920282f200608131803010629210c1a0d001d040e4c2912111a4c",
// 	"1d07144304070c06004951292920282f200608131803010629210c1a0d001d040e4c2912111a322608071d1757",
// }

// func init() {

// 	encodedLists := [][]string{
// 		obfEdrList,
// 		obfRegistryReconList,
// 		obfRegistrySearchList,
// 	}
// 	decodedLists := []*[]string{
// 		&EdrList,
// 		&RegistryReconList,
// 		&RegistrySearchList,
// 	}

// 	for i, encodedList := range encodedLists {
// 		decodedList := decodedLists[i]
// 		for _, index := range encodedList {
// 			deHex, _ := hex.DecodeString(index)
// 			decoded := xorObf(deHex, key)
// 			*decodedList = append(*decodedList, string(decoded))
// 		}
// 	}
// }

// func xorObf(input, key []byte) []byte {
// 	ret := make([]byte, len(input))
// 	for i := 0; i < len(input); i++ {
// 		ret[i] = input[i] ^ key[i%len(key)]
// 	}
// 	return ret
// }

// Edrlist is a list of edrs.
var EdrList = []string{
	"activeconsole",
	"amsi.dll",
	"anti malware",
	"anti-malware",
	"antimalware",
	"anti virus",
	"anti-virus",
	"antivirus",
	"appsense",
	"authtap",
	"avast",
	"avecto",
	"canary",
	"carbonblack",
	"carbon black",
	"cb.exe",
	"ciscoamp",
	"cisco amp",
	"countercept",
	"countertack",
	"cramtray",
	"crssvc",
	"crowdstrike",
	"csagent",
	"csfalcon",
	"csshell",
	"cybereason",
	"cyclorama",
	"cylance",
	"cyoptics",
	"cyupdate",
	"cyvera",
	"cyserver",
	"cytray",
	"darktrace",
	"defendpoint",
	"defender",
	"eectrl",
	"elastic",
	"endgame",
	"f-secure",
	"forcepoint",
	"fireeye",
	"groundling",
	"GRRservic",
	"inspector",
	"ivanti",
	"kaspersky",
	"lacuna",
	"logrhythm",
	"malware",
	"mandiant",
	"mcafee",
	"morphisec",
	"msascuil",
	"msmpeng",
	"nissrv",
	"omni",
	"omniagent",
	"osquery",
	"Palo Alto Networks",
	"pgeposervice",
	"pgsystemtray",
	"privilegeguard",
	"procwall",
	"protectorservic",
	"qradar",
	"redcloak",
	"secureworks",
	"securityhealthservice",
	"semlaunchsv",
	"sentinel",
	"sepliveupdat",
	"sisidsservice",
	"sisipsservice",
	"sisipsutil",
	"smc.exe",
	"smcgui",
	"snac64",
	"sophos",
	"splunk",
	"srtsp",
	"symantec",
	"symcorpu",
	"symefasi",
	"sysinternal",
	"sysmon",
	"tanium",
	"tda.exe",
	"tdawork",
	"tpython",
	"vectra",
	"wincollect",
	"windowssensor",
	"wireshark",
	"threat",
	"xagt.exe",
	"xagtnotif.exe",
}

var ReconList = []string{
	"ProductName",
	"CSDVersion",
	"CurrentVersion",
	"CurrentBuild",
	"SystemRoot",
	"RegisteredOrganization",
	"Domain",
	"DhcpNameServer",
	"DhcpDomain",
	"SystemManufacturer",
	"SystemProductName",
	"LocalAccountTokenFilterPolicy",
	"LsaCfgFlags",
}

type EDRType string

var (
	WinDefenderEDR EDRType = "defender"
	KaskperskyEDR  EDRType = "kaspersky"
	CrowdstrikeEDR EDRType = "crowdstrike"
	McafeeEDR      EDRType = "mcafee"
	SymantecEDR    EDRType = "symantec"
	CylanceEDR     EDRType = "cylance"
)

var McafeeList = []string{
	"Mcafee\\",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
}

var SymantecList = []string{
	"Symantec",
	"Symantec Endpoint Protection\\",
}

// var WinDefender = []string{
// 	"Windows Defender",
// 	"DpaDisabled",
// 	"DisableRealTimeMonitoring",
// }

var WinDefenderATP = []string{}

var CarbonBlack = []string{
	"CarbonBlack\\",
	"CbDefense\\",
	"SensorVersion",
}

var CrowdStrike = []string{
	"CrowdStrike\\",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsDeviceControl.inf",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsFirmwareAnalysis.inf",
}

var Cylance = []string{
	"Cylance\\",
	"Cylance0",
	"Cylance1",
	"Cylance2",
}

var FireEye = []string{
	"FireEye",
}

var SentinelOne = []string{
	"Sentinel Labs\\",
	"Sentinel Agent\\",
	"externalID",
}

var RegistryReconList = []string{
	"Sentinel Labs\\",
	"Sentinel Agent\\",
	"externalID",
	"FireEye",
	"Cylance\\",
	"Cylance0",
	"Cylance1",
	"Cylance2",
	"CrowdStrike\\",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsDeviceControl.inf",
	"%SYSTEMROOT%\\system32\\drivers\\crowdstrike\\CsFirmwareAnalysis.inf",
	"Mcafee\\",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
	"Symantec",
	"Symantec Endpoint Protection\\",
	"Windows Defender",
	"DpaDisabled",
	"DisableRealTimeMonitoring",
	"CarbonBlack\\",
	"CbDefense\\",
	"SensorVersion",
}

var RegistrySearchList = []string{
	`reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"`,
	`reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS"`,
	`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
	`reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"`,
	`reg query "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard"`,
	`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"`,
	`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"`,
	`reg query HKLM\Software\McAfee\Endpoint\AV`,
	`reg query HKLM\Software\Symantec`,
	`reg query HKLM\Software\Cylance\Desktop`,
	`reg query HKLM\Software\CbDefense`,
	`reg query HKLM\Software\CrowdStrike\InfDb`,
	`reg query "HKLM\Software\Sentinel Labs"`,
	`reg query "HKLM\Software\Sentinel Labs\Agent"`,
}

//encoder
// for _, index := range EdrList {
// input := []byte(index)
// encoded := hex.EncodeToString(xorObf(input, key))
// ObfEdrList = append(ObfEdrList, fmt.Sprintf("\"%s\",\n", encoded))
