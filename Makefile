
proto:
	protoc --go_out=plugins=grpc:. pkg/structs/*.proto
