all: build

build:
	go build -ldflags="-w -s" -o EDRHunt.exe github.com/fourcorelabs/edrhunt/cmd/EDRHunt
garble-build:
	garble -literals build -ldflags="-w -s" -o EDRHunt.exe github.com/fourcorelabs/edrhunt/cmd/EDRHunt
local:
	go build -ldflags="-w -s" -o EDRHunt.exe github.com/fourcorelabs/edrhunt/cmd/EDRHunt
run:
	go run -ldflags="-w -s" github.com/fourcorelabs/edrhunt/cmd/EDRHunt all
drivers:
	go run -ldflags="-w -s" github.com/fourcorelabs/edrhunt/cmd/EDRHunt -d
avwmi:
	go run -ldflags="-w -s" github.com/fourcorelabs/edrhunt/cmd/EDRHunt -w
