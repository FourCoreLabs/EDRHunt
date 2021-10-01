# EDR-Recon

[![goreleaser](https://github.com/FourCoreLabs/edrRecon/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/FourCoreLabs/edrRecon/actions/workflows/goreleaser.yml)

EDR-Recon scans Windows services, drivers, processes, registry for installed EDRs.

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
```

- Find processes matching EDR keywords

```
$ .\edrRecon.exe -p
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
