# EDRHunt

[![goreleaser](https://github.com/FourCoreLabs/EDRHunt/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/FourCoreLabs/EDRHunt/actions/workflows/goreleaser.yml)

EDRHunt scans Windows services, drivers, processes, registry for installed EDRs. Read more about EDRHunt [here](https://www.fourcore.vision/blogs/Red-Team-Adventure:-Digging-into-Windows-Endpoints-for-EDRs-and-profit-cUf).

[![asciicast](https://asciinema.org/a/P8i99w9mI497qUPTNbdwYWcwQ.svg)](https://asciinema.org/a/P8i99w9mI497qUPTNbdwYWcwQ)

## Install

- Binary
  - Download the latest release from the release section. Releases are built for windows/amd64.

- Go
  - Requires Go to be installed on system. Tested on Go1.17+.
  - `go install github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt@master`

## Usage

- Find installed EDRs

```
$ .\EDRHunt.exe scan
[EDR]
Detected EDR: Windows Defender
Detected EDR: Kaspersky Security
```

- Scan Everything
```
$ .\EDRHunt.exe all
Running in user mode, escalate to admin for more details.
Scanning processes, services, drivers, and registry...
[PROCESSES]

Suspicious Process Name: MsMpEng.exe
Description: MsMpEng.exe
Caption: MsMpEng.exe
Binary:
ProcessID: 6764
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [msmpeng]


Suspicious Process Name: NisSrv.exe
Description: NisSrv.exe
Caption: NisSrv.exe
Binary:
ProcessID: 9840
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [nissrv]
...
```

- Find processes matching EDR keywords

```
$ .\EDRHunt.exe -p
Running in user mode, escalate to admin for more details.
[PROCESSES]

Suspicious Process Name: MsMpEng.exe
Description: MsMpEng.exe
Caption: MsMpEng.exe
Binary:
ProcessID: 6764
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [msmpeng]


Suspicious Process Name: NisSrv.exe
Description: NisSrv.exe
Caption: NisSrv.exe
Binary:
ProcessID: 9840
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [nissrv]


Suspicious Process Name: SecurityHealthService.exe
Description: SecurityHealthService.exe
Caption: SecurityHealthService.exe
Binary:
ProcessID: 13720
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [securityhealthservice]
...
```

- Find services matching EDR keywords

```
$ .\EDRHunt.exe -s
```

- Find drivers matching EDR keywords

```
$ .\EDRHunt.exe -d
```

- Find registry keys matching EDR keywords

```
$ .\EDRHunt.exe -r
```

## Detections

EDR Detections Currently Available

- Windows Defender
- Kaspersky Security
- Symantec Security
- Crowdstrike Security
- Mcafee Security
- Cylance Security
- Carbon Black
- SentinelOne
- FireEye

More to be added soon.

## Community

Would appreciate if you ran EDRHunt on your own deployments and test the detections! Thanks.
