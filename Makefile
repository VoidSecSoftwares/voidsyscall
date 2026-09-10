.PHONY: all agent-linux server

all: agent-win server-win server-linux server-darwin

agent-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o build/voidsyscall-agent.exe ./cmd/agent

agent-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/voidsyscall-agent-linux ./cmd/agent

server-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o build/voidsyscall-server.exe ./cmd/server

server-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/voidsyscall-server-linux ./cmd/server

server-darwin:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o build/voidsyscall-server-darwin ./cmd/server

obfuscate:
	GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o build/voidsyscall-agent-obf.exe ./cmd/agent

vet:
	go vet ./...

test:
	go test ./...