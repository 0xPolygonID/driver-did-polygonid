# Post man 'newman' utility should be installed
# https://learning.postman.com/docs/running-collections/using-newman-cli/command-line-integration-with-newman/
e2e:
	newman run tests/e2e/http_nameservice.postman_collection.json -g tests/e2e/dev_env.json

register-domain:
	go run cmd/registrar/main.go

lint:
	 golangci-lint --config .golangci.yml run

test:
	go test ./...
