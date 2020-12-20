LDFLAGS := "-s -w "
.PHONY: test
test:
	cd pkg; go test ./...
.PHONY: build
build:
	mkdir -p bin
	go build -ldflags=${LDFLAGS} -o bin/iptables-match ./
alpine:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags=${LDFLAGS} -o bin/iptables-match ./
run:
	chmod +x bin/iptables-match &&./bin/iptables-match
trace:
	LOGLEVEL=TRACE ./bin/iptables-match
debug:
	LOGLEVEL=DEBUG ./bin/iptables-match
clean:
	rm -r bin
inject:
	kubectl cp bin/iptables-match `kubectl get pod -n kube-system | grep kube-proxy | cut -d" " -f1 | head -1`:/iptables-match -n kube-system
intercept:
	kubectl exec -ti `kubectl get pod -n kube-system | grep kube-proxy | cut -d" " -f1 | head -1` /iptables-match -n kube-system