COMMIT = $$(git describe --tags --always)
DATE = $$(date --utc '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = "-X main.commit=\"$(COMMIT)\" -X main.date=\"$(DATE)\""
RELEASE_BUILD_LDFLAGS = "$(BUILD_LDFLAGS) -s -w"

.PHONY: build
build:
	go build -ldflags=$(BUILD_LDFLAGS)

.PHONY: test
test:
	go test -v ./...

.PHONY: cover
cover: devel-deps
	goveralls -service=travis-ci

.PHONY: devel-deps
devel-deps:
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go get github.com/motemen/gobump
	go get github.com/Songmu/ghch
	go get github.com/Songmu/goxz
	go get github.com/tcnksm/ghr

.PHONY: crossbuild
crossbuild: devel-deps
	$(eval ver = $(shell gobump show -r))
	goxz -pv=v$(ver)) -build-ldflags=$(RELEASE_BUILD_LDFLAGS) \
	  -d=./dist/v$(shell gobump show -r) .

.PHONY: release
release:
	_tools/release
	_tools/upload_artifacts