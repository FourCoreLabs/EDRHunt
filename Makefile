all:
	go build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon/cmd/main
garble-build:
	garble -literals build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon/cmd/main
local:
	go build -ldflags="-w -s" -o edrRecon.exe cmd\main\main.go
run:
	go run -ldflags="-w -s" cmd\main\main.go -a
