.PHONY: all build test bench clean e2e
BENCH ?= .
TEST ?= .

all: build test

build:
	go build -o secretscalpel .

test:
	go test -v ./redactor/... -run $(TEST)

e2e:
	chmod +x tests/e2e.sh && ./tests/e2e.sh

bench:
	go test -bench=$(BENCH) -benchmem ./redactor/...

clean:
	rm -f secretscalpel

pprof:
	go test -bench=$(BENCH) -benchmem -cpuprofile=cpu.out -memprofile=mem.out ./redactor/...

docker:
	docker build -t secretscalpel .