module github.com/butonic/ldapserver

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.0
	contrib.go.opencensus.io/exporter/ocagent v0.5.0
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/stdr v0.0.0-20190808155957-db4f46c40425
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3
	github.com/micro/cli v0.2.0
	github.com/micro/go-micro v1.17.1
	github.com/micro/grpc-go v0.0.0-20190130160115-549af9fb4bf2
	github.com/oklog/run v1.0.0
	github.com/openzipkin/zipkin-go v0.1.6
	github.com/owncloud/ocis-devldap v0.0.0-20191205143003-809a64c36b1e
	github.com/spf13/viper v1.5.0
	go.opencensus.io v0.22.2
	golang.org/x/net v0.0.0-20191204025024-5ee1b9f4859a
	google.golang.org/grpc v1.25.1
)

go 1.13
