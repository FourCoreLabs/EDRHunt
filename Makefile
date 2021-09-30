all:
	go build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon
garble-build:
	garble -literals build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon
local:
	go build -ldflags="-w -s" -o edrRecon.exe main.go
run:
	go run -ldflags="-w -s" main.go -a
