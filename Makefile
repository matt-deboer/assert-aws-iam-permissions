VERSION        ?= $(shell git describe --tags --always )
TARGET         ?= $(shell basename `git rev-parse --show-toplevel`)
TEST           ?= $(shell go list ./... | grep -v /vendor/)
REPOSITORY     := mattdeboer/assert-aws-iam-permissions
DOCKER_IMAGE   ?= ${REPOSITORY}:${VERSION}
BRANCH         ?= $(shell git rev-parse --abbrev-ref HEAD)
REVISION       ?= $(shell git rev-parse HEAD)
LD_FLAGS       ?= -s -X github.com/matt-deboer/assert-aws-iam-permissions/pkg/version.Name=$(TARGET) \
	-X github.com/matt-deboer/assert-aws-iam-permissions/pkg/version.Revision=$(REVISION) \
	-X github.com/matt-deboer/assert-aws-iam-permissions/pkg/version.Branch=$(BRANCH) \
	-X github.com/matt-deboer/assert-aws-iam-permissions/pkg/version.Version=$(VERSION)

default: test build

test:
	go test -v -cover -run=$(RUN) $(TEST)

build: clean
	@go build -v -o bin/$(TARGET) -ldflags "$(LD_FLAGS)+local_changes" ./pkg/server

release: clean
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build \
		-a -tags netgo \
		-a -installsuffix cgo \
    -ldflags "$(LD_FLAGS)" \
		-o bin/$(TARGET) ./pkg/server

ca-certificates.crt:
	@-docker rm -f assert-aws-iam-permissions_cacerts
	@docker run --name assert-aws-iam-permissions_cacerts debian:latest bash -c 'apt-get update && apt-get install -y ca-certificates'
	@docker cp assert-aws-iam-permissions_cacerts:/etc/ssl/certs/ca-certificates.crt .
	@docker rm -f assert-aws-iam-permissions_cacerts

docker: ca-certificates.crt
	@echo "Building ${DOCKER_IMAGE}..."
	@docker build -t ${DOCKER_IMAGE} -f Dockerfile.scratch .
	@docker build -t ${DOCKER_IMAGE}-alpine -f Dockerfile.alpine .

clean:
	@rm -rf bin/