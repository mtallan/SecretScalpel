.PHONY: all build test bench clean
BENCH ?= .

all: build test

build:
	go build -o secretscalpel .

test:
	go test -v ./redactor/...

bench:
	go test -bench=$(BENCH) -benchmem ./redactor/...

clean:
	rm -f secretscalpel

pprof:
	go test -bench=$(BENCH) -benchmem -cpuprofile=cpu.out -memprofile=mem.out ./redactor/...

docker:
	docker build -t secretscalpel .