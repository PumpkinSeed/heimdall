
proto:
	protoc --go_out=. --go-grpc_out=. pkg/structs/*.proto
