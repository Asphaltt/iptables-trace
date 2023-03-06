
.PHONY: kernel all trace

all: kernel trace

kernel:
	cd kernel && make

trace:
	go generate && go build
