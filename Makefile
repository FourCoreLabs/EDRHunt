all: build

build:
	go build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon/cmd/edrRecon
garble-build:
	garble -literals build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon/cmd/edrRecon
local:
	go build -ldflags="-w -s" -o edrRecon.exe main.go
run:
	go run -ldflags="-w -s" main.go -a
