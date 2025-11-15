build:
	go build -o portmon
cp:
	cp portmon ~/.local/bin/
	
install: build cp