all: build

build:
	go build -ldflags="-w -s" -o EDRHunt.exe github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt
garble-build:
	garble -literals build -ldflags="-w -s" -o EDRHunt.exe github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt
local:
	go build -ldflags="-w -s" -o EDRHunt.exe github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt
run:
	go run -ldflags="-w -s" github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt all
drivers:
	go run -ldflags="-w -s" github.com/FourCoreLabs/EDRHunt/cmd/EDRHunt -d
