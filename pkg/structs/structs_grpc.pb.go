// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package structs

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// EncryptionClient is the client API for Encryption service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EncryptionClient interface {
	CreateKey(ctx context.Context, in *Key, opts ...grpc.CallOption) (*KeyResponse, error)
	ReadKey(ctx context.Context, in *KeyName, opts ...grpc.CallOption) (*KeyResponse, error)
	DeleteKey(ctx context.Context, in *KeyName, opts ...grpc.CallOption) (*KeyResponse, error)
	ListKeys(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*KeyListResponse, error)
	Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*CryptoResult, error)
	Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*CryptoResult, error)
	Hash(ctx context.Context, in *HashRequest, opts ...grpc.CallOption) (*HashResponse, error)
	GenerateHMAC(ctx context.Context, in *HMACRequest, opts ...grpc.CallOption) (*HMACResponse, error)
	Sign(ctx context.Context, in *SignParameters, opts ...grpc.CallOption) (*SignResponse, error)
	VerifySigned(ctx context.Context, in *VerificationRequest, opts ...grpc.CallOption) (*VerificationResponse, error)
	Rewrap(ctx context.Context, in *RewrapRequest, opts ...grpc.CallOption) (*CryptoResult, error)
	UpdateKeyConfiguration(ctx context.Context, in *KeyConfig, opts ...grpc.CallOption) (*Empty, error)
	RotateKey(ctx context.Context, in *RotateRequest, opts ...grpc.CallOption) (*Empty, error)
	ExportKey(ctx context.Context, in *ExportRequest, opts ...grpc.CallOption) (*ExportResult, error)
	BackupKey(ctx context.Context, in *BackupRequest, opts ...grpc.CallOption) (*BackupResult, error)
	RestoreKey(ctx context.Context, in *RestoreRequest, opts ...grpc.CallOption) (*Empty, error)
	GenerateKey(ctx context.Context, in *GenerateKeyRequest, opts ...grpc.CallOption) (*GenerateKeyResponse, error)
	GenerateRandomBytes(ctx context.Context, in *GenerateBytesRequest, opts ...grpc.CallOption) (*GenerateBytesResponse, error)
	Health(ctx context.Context, in *HealthRequest, opts ...grpc.CallOption) (*HealthResponse, error)
}

type encryptionClient struct {
	cc grpc.ClientConnInterface
}

func NewEncryptionClient(cc grpc.ClientConnInterface) EncryptionClient {
	return &encryptionClient{cc}
}

func (c *encryptionClient) CreateKey(ctx context.Context, in *Key, opts ...grpc.CallOption) (*KeyResponse, error) {
	out := new(KeyResponse)
	err := c.cc.Invoke(ctx, "/Encryption/CreateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) ReadKey(ctx context.Context, in *KeyName, opts ...grpc.CallOption) (*KeyResponse, error) {
	out := new(KeyResponse)
	err := c.cc.Invoke(ctx, "/Encryption/ReadKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) DeleteKey(ctx context.Context, in *KeyName, opts ...grpc.CallOption) (*KeyResponse, error) {
	out := new(KeyResponse)
	err := c.cc.Invoke(ctx, "/Encryption/DeleteKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) ListKeys(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*KeyListResponse, error) {
	out := new(KeyListResponse)
	err := c.cc.Invoke(ctx, "/Encryption/ListKeys", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*CryptoResult, error) {
	out := new(CryptoResult)
	err := c.cc.Invoke(ctx, "/Encryption/Encrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*CryptoResult, error) {
	out := new(CryptoResult)
	err := c.cc.Invoke(ctx, "/Encryption/Decrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Hash(ctx context.Context, in *HashRequest, opts ...grpc.CallOption) (*HashResponse, error) {
	out := new(HashResponse)
	err := c.cc.Invoke(ctx, "/Encryption/Hash", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) GenerateHMAC(ctx context.Context, in *HMACRequest, opts ...grpc.CallOption) (*HMACResponse, error) {
	out := new(HMACResponse)
	err := c.cc.Invoke(ctx, "/Encryption/GenerateHMAC", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Sign(ctx context.Context, in *SignParameters, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	err := c.cc.Invoke(ctx, "/Encryption/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) VerifySigned(ctx context.Context, in *VerificationRequest, opts ...grpc.CallOption) (*VerificationResponse, error) {
	out := new(VerificationResponse)
	err := c.cc.Invoke(ctx, "/Encryption/VerifySigned", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Rewrap(ctx context.Context, in *RewrapRequest, opts ...grpc.CallOption) (*CryptoResult, error) {
	out := new(CryptoResult)
	err := c.cc.Invoke(ctx, "/Encryption/Rewrap", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) UpdateKeyConfiguration(ctx context.Context, in *KeyConfig, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/Encryption/UpdateKeyConfiguration", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) RotateKey(ctx context.Context, in *RotateRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/Encryption/RotateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) ExportKey(ctx context.Context, in *ExportRequest, opts ...grpc.CallOption) (*ExportResult, error) {
	out := new(ExportResult)
	err := c.cc.Invoke(ctx, "/Encryption/ExportKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) BackupKey(ctx context.Context, in *BackupRequest, opts ...grpc.CallOption) (*BackupResult, error) {
	out := new(BackupResult)
	err := c.cc.Invoke(ctx, "/Encryption/BackupKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) RestoreKey(ctx context.Context, in *RestoreRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/Encryption/RestoreKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) GenerateKey(ctx context.Context, in *GenerateKeyRequest, opts ...grpc.CallOption) (*GenerateKeyResponse, error) {
	out := new(GenerateKeyResponse)
	err := c.cc.Invoke(ctx, "/Encryption/GenerateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) GenerateRandomBytes(ctx context.Context, in *GenerateBytesRequest, opts ...grpc.CallOption) (*GenerateBytesResponse, error) {
	out := new(GenerateBytesResponse)
	err := c.cc.Invoke(ctx, "/Encryption/GenerateRandomBytes", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Health(ctx context.Context, in *HealthRequest, opts ...grpc.CallOption) (*HealthResponse, error) {
	out := new(HealthResponse)
	err := c.cc.Invoke(ctx, "/Encryption/Health", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptionServer is the server API for Encryption service.
// All implementations must embed UnimplementedEncryptionServer
// for forward compatibility
type EncryptionServer interface {
	CreateKey(context.Context, *Key) (*KeyResponse, error)
	ReadKey(context.Context, *KeyName) (*KeyResponse, error)
	DeleteKey(context.Context, *KeyName) (*KeyResponse, error)
	ListKeys(context.Context, *Empty) (*KeyListResponse, error)
	Encrypt(context.Context, *EncryptRequest) (*CryptoResult, error)
	Decrypt(context.Context, *DecryptRequest) (*CryptoResult, error)
	Hash(context.Context, *HashRequest) (*HashResponse, error)
	GenerateHMAC(context.Context, *HMACRequest) (*HMACResponse, error)
	Sign(context.Context, *SignParameters) (*SignResponse, error)
	VerifySigned(context.Context, *VerificationRequest) (*VerificationResponse, error)
	Rewrap(context.Context, *RewrapRequest) (*CryptoResult, error)
	UpdateKeyConfiguration(context.Context, *KeyConfig) (*Empty, error)
	RotateKey(context.Context, *RotateRequest) (*Empty, error)
	ExportKey(context.Context, *ExportRequest) (*ExportResult, error)
	BackupKey(context.Context, *BackupRequest) (*BackupResult, error)
	RestoreKey(context.Context, *RestoreRequest) (*Empty, error)
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GenerateRandomBytes(context.Context, *GenerateBytesRequest) (*GenerateBytesResponse, error)
	Health(context.Context, *HealthRequest) (*HealthResponse, error)
	mustEmbedUnimplementedEncryptionServer()
}

// UnimplementedEncryptionServer must be embedded to have forward compatible implementations.
type UnimplementedEncryptionServer struct {
}

func (UnimplementedEncryptionServer) CreateKey(context.Context, *Key) (*KeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKey not implemented")
}
func (UnimplementedEncryptionServer) ReadKey(context.Context, *KeyName) (*KeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReadKey not implemented")
}
func (UnimplementedEncryptionServer) DeleteKey(context.Context, *KeyName) (*KeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteKey not implemented")
}
func (UnimplementedEncryptionServer) ListKeys(context.Context, *Empty) (*KeyListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListKeys not implemented")
}
func (UnimplementedEncryptionServer) Encrypt(context.Context, *EncryptRequest) (*CryptoResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Encrypt not implemented")
}
func (UnimplementedEncryptionServer) Decrypt(context.Context, *DecryptRequest) (*CryptoResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Decrypt not implemented")
}
func (UnimplementedEncryptionServer) Hash(context.Context, *HashRequest) (*HashResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Hash not implemented")
}
func (UnimplementedEncryptionServer) GenerateHMAC(context.Context, *HMACRequest) (*HMACResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateHMAC not implemented")
}
func (UnimplementedEncryptionServer) Sign(context.Context, *SignParameters) (*SignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}
func (UnimplementedEncryptionServer) VerifySigned(context.Context, *VerificationRequest) (*VerificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifySigned not implemented")
}
func (UnimplementedEncryptionServer) Rewrap(context.Context, *RewrapRequest) (*CryptoResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Rewrap not implemented")
}
func (UnimplementedEncryptionServer) UpdateKeyConfiguration(context.Context, *KeyConfig) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateKeyConfiguration not implemented")
}
func (UnimplementedEncryptionServer) RotateKey(context.Context, *RotateRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RotateKey not implemented")
}
func (UnimplementedEncryptionServer) ExportKey(context.Context, *ExportRequest) (*ExportResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExportKey not implemented")
}
func (UnimplementedEncryptionServer) BackupKey(context.Context, *BackupRequest) (*BackupResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BackupKey not implemented")
}
func (UnimplementedEncryptionServer) RestoreKey(context.Context, *RestoreRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RestoreKey not implemented")
}
func (UnimplementedEncryptionServer) GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateKey not implemented")
}
func (UnimplementedEncryptionServer) GenerateRandomBytes(context.Context, *GenerateBytesRequest) (*GenerateBytesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateRandomBytes not implemented")
}
func (UnimplementedEncryptionServer) Health(context.Context, *HealthRequest) (*HealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Health not implemented")
}
func (UnimplementedEncryptionServer) mustEmbedUnimplementedEncryptionServer() {}

// UnsafeEncryptionServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to EncryptionServer will
// result in compilation errors.
type UnsafeEncryptionServer interface {
	mustEmbedUnimplementedEncryptionServer()
}

func RegisterEncryptionServer(s grpc.ServiceRegistrar, srv EncryptionServer) {
	s.RegisterService(&Encryption_ServiceDesc, srv)
}

func _Encryption_CreateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Key)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).CreateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/CreateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).CreateKey(ctx, req.(*Key))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_ReadKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyName)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).ReadKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/ReadKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).ReadKey(ctx, req.(*KeyName))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_DeleteKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyName)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).DeleteKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/DeleteKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).DeleteKey(ctx, req.(*KeyName))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_ListKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).ListKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/ListKeys",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).ListKeys(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Encrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Encrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Encrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Encrypt(ctx, req.(*EncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Decrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Decrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Decrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Decrypt(ctx, req.(*DecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Hash_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HashRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Hash(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Hash",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Hash(ctx, req.(*HashRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_GenerateHMAC_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HMACRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).GenerateHMAC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/GenerateHMAC",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).GenerateHMAC(ctx, req.(*HMACRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Sign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignParameters)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Sign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Sign(ctx, req.(*SignParameters))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_VerifySigned_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).VerifySigned(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/VerifySigned",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).VerifySigned(ctx, req.(*VerificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Rewrap_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RewrapRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Rewrap(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Rewrap",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Rewrap(ctx, req.(*RewrapRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_UpdateKeyConfiguration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).UpdateKeyConfiguration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/UpdateKeyConfiguration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).UpdateKeyConfiguration(ctx, req.(*KeyConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_RotateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RotateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).RotateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/RotateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).RotateKey(ctx, req.(*RotateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_ExportKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).ExportKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/ExportKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).ExportKey(ctx, req.(*ExportRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_BackupKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BackupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).BackupKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/BackupKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).BackupKey(ctx, req.(*BackupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_RestoreKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RestoreRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).RestoreKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/RestoreKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).RestoreKey(ctx, req.(*RestoreRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_GenerateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).GenerateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/GenerateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).GenerateKey(ctx, req.(*GenerateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_GenerateRandomBytes_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateBytesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).GenerateRandomBytes(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/GenerateRandomBytes",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).GenerateRandomBytes(ctx, req.(*GenerateBytesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Health_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Encryption/Health",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Health(ctx, req.(*HealthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Encryption_ServiceDesc is the grpc.ServiceDesc for Encryption service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Encryption_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "Encryption",
	HandlerType: (*EncryptionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKey",
			Handler:    _Encryption_CreateKey_Handler,
		},
		{
			MethodName: "ReadKey",
			Handler:    _Encryption_ReadKey_Handler,
		},
		{
			MethodName: "DeleteKey",
			Handler:    _Encryption_DeleteKey_Handler,
		},
		{
			MethodName: "ListKeys",
			Handler:    _Encryption_ListKeys_Handler,
		},
		{
			MethodName: "Encrypt",
			Handler:    _Encryption_Encrypt_Handler,
		},
		{
			MethodName: "Decrypt",
			Handler:    _Encryption_Decrypt_Handler,
		},
		{
			MethodName: "Hash",
			Handler:    _Encryption_Hash_Handler,
		},
		{
			MethodName: "GenerateHMAC",
			Handler:    _Encryption_GenerateHMAC_Handler,
		},
		{
			MethodName: "Sign",
			Handler:    _Encryption_Sign_Handler,
		},
		{
			MethodName: "VerifySigned",
			Handler:    _Encryption_VerifySigned_Handler,
		},
		{
			MethodName: "Rewrap",
			Handler:    _Encryption_Rewrap_Handler,
		},
		{
			MethodName: "UpdateKeyConfiguration",
			Handler:    _Encryption_UpdateKeyConfiguration_Handler,
		},
		{
			MethodName: "RotateKey",
			Handler:    _Encryption_RotateKey_Handler,
		},
		{
			MethodName: "ExportKey",
			Handler:    _Encryption_ExportKey_Handler,
		},
		{
			MethodName: "BackupKey",
			Handler:    _Encryption_BackupKey_Handler,
		},
		{
			MethodName: "RestoreKey",
			Handler:    _Encryption_RestoreKey_Handler,
		},
		{
			MethodName: "GenerateKey",
			Handler:    _Encryption_GenerateKey_Handler,
		},
		{
			MethodName: "GenerateRandomBytes",
			Handler:    _Encryption_GenerateRandomBytes_Handler,
		},
		{
			MethodName: "Health",
			Handler:    _Encryption_Health_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/structs/structs.proto",
}
