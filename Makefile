all:
	go build -ldflags="-w -s" -o edrRecon.exe github.com/FourCoreLabs/edrRecon/cmd/main
