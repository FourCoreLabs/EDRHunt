# EDR-Recon

[![goreleaser](https://github.com/FourCoreLabs/edrRecon/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/FourCoreLabs/edrRecon/actions/workflows/goreleaser.yml)

EDR-Recon scans Windows services, drivers, processes, registry for installed EDRs.

[![asciicast](https://asciinema.org/a/3UEKxkSE2nlBbEhL5HDOapYRn.svg)](https://asciinema.org/a/3UEKxkSE2nlBbEhL5HDOapYRn)

## Install

- Binary
  - Download the latest release from the release section. Releases are built for windows/amd64.

- Go
  - Requires Go to be installed on system. Tested on Go1.17+.
  - `go install github.com/FourCoreLabs/edrRecon/cmd/edrRecon@master`

## Usage

- Find installed EDRs

```
$ .\edrRecon.exe scan
[EDR]
Detected EDR: Windows Defender
Detected EDR: Kaspersky Security
```

- Scan Everything
```
$ .\edrRecon.exe all
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
$ .\edrRecon.exe -p
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
$ .\edrRecon.exe -s
```

- Find drivers matching EDR keywords

```
$ .\edrRecon.exe -d
```

- Find registry keys matching EDR keywords

```
$ .\edrRecon.exe -r
```

## Detections

EDR Detections Currently Available

- Windows Defender
- Kaspersky Security

More to be added soon.
