# EDRHunt

[![goreleaser](https://github.com/FourCoreLabs/EDRHunt/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/FourCoreLabs/EDRHunt/actions/workflows/goreleaser.yml)

EDRHunt scans Windows services, drivers, processes, registry, wmi for installed EDRs (Endpoint Detection And Response). Read more about EDRHunt [here](https://www.fourcore.vision/blogs/red-team-adventure-windows-endpoints-edr-edrhunt).

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
Scanning processes, services, drivers, wmi, and registry...
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

- Find drivers matching EDR keywords

```
    __________  ____     __  ____  ___   ________
   / ____/ __ \/ __ \   / / / / / / / | / /_  __/
  / __/ / / / / /_/ /  / /_/ / / / /  |/ / / /
 / /___/ /_/ / _, _/  / __  / /_/ / /|  / / /
/_____/_____/_/ |_|  /_/ /_/\____/_/ |_/ /_/

FourCore Labs (https://fourcore.vision) | Version: 1.1

Running in user mode, escalate to admin for more details.
[DRIVERS]
Suspicious Driver Module: WdFilter.sys
Driver FilePath: c:\windows\system32\drivers\wd\wdfilter.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: WdFilter.sys
        InternalFileName: WdFilter
        Company Name: Microsoft Corporation
        FileDescription: Microsoft antimalware file system filter driver
        ProductVersion: 4.18.2109.6
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [antimalware malware]

Suspicious Driver Module: hvsifltr.sys
Driver FilePath: c:\windows\system32\drivers\hvsifltr.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: hvsifltr.sys.mui
        InternalFileName: hvsifltr.sys
        Company Name: Microsoft Corporation
        FileDescription: Microsoft Defender Application Guard Filter Driver
        ProductVersion: 10.0.19041.1
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [defender]

Suspicious Driver Module: WdNisDrv.sys
Driver FilePath: c:\windows\system32\drivers\wd\wdnisdrv.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: wdnisdrv.sys
        InternalFileName: wdnisdrv.sys
        Company Name: Microsoft Corporation
        FileDescription: Windows Defender Network Stream Filter
        ProductVersion: 4.18.2109.6
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [defender]
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


- Find WMI Repository keys matching EDR keywords

```
$ .\EDRHunt.exe -w
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
- Elastic EDR
- Qualys EDR
- Trend Micro EDR
- ESET EDR
- Cybereason EDR
- BitDefender EDR
- Checkpoint EDR
- Cynet EDR
- DeepInstinct EDR
- Sophos EDR
- Fortinet EDR
- MalwareBytes EDR

More to be added soon.

## Community

Would appreciate if you ran EDRHunt on your own deployments and test the detections! Thanks.
