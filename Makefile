.PHONY: build
build:
	GOOS=linux GOARCH=386 go build

.PHONY: test
test:
	go test -v ./...