# 원격 전송 도구 제한으로 "Makefile" 이름으로 저장할 수 없어 build.mk 로 저장함. (Windows 에서는 scripts\build.ps1 사용)
# 사용: make -f build.mk build   (원하면 파일명을 Makefile 로 바꿔 make build)
# Windows 용 에이전트 빌드 (Linux/macOS/Windows 어디서나 크로스 컴파일 가능, CGO 불필요)
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build vet passive tidy
tidy:
	go mod tidy
build: passive
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/edr-agent-amd64.exe ./cmd/edr-agent
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/edr-agent-arm64.exe ./cmd/edr-agent
vet:
	GOOS=windows go vet ./...
passive:
	bash ../scripts/check-passive.sh
