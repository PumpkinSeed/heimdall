// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.14.0
// source: pkg/structs/structs.proto

package structs

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EncryptionType int32

const (
	EncryptionType_AES256_GCM96      EncryptionType = 0
	EncryptionType_CHACHA20_POLY1305 EncryptionType = 1
)

// Enum value maps for EncryptionType.
var (
	EncryptionType_name = map[int32]string{
		0: "AES256_GCM96",
		1: "CHACHA20_POLY1305",
	}
	EncryptionType_value = map[string]int32{
		"AES256_GCM96":      0,
		"CHACHA20_POLY1305": 1,
	}
)

func (x EncryptionType) Enum() *EncryptionType {
	p := new(EncryptionType)
	*p = x
	return p
}

func (x EncryptionType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncryptionType) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_structs_structs_proto_enumTypes[0].Descriptor()
}

func (EncryptionType) Type() protoreflect.EnumType {
	return &file_pkg_structs_structs_proto_enumTypes[0]
}

func (x EncryptionType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncryptionType.Descriptor instead.
func (EncryptionType) EnumDescriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{0}
}

type Status int32

const (
	Status_UNKNOWN Status = 0
	Status_SUCCESS Status = 1
	Status_ERROR   Status = 2
)

// Enum value maps for Status.
var (
	Status_name = map[int32]string{
		0: "UNKNOWN",
		1: "SUCCESS",
		2: "ERROR",
	}
	Status_value = map[string]int32{
		"UNKNOWN": 0,
		"SUCCESS": 1,
		"ERROR":   2,
	}
)

func (x Status) Enum() *Status {
	p := new(Status)
	*p = x
	return p
}

func (x Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Status) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_structs_structs_proto_enumTypes[1].Descriptor()
}

func (Status) Type() protoreflect.EnumType {
	return &file_pkg_structs_structs_proto_enumTypes[1]
}

func (x Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Status.Descriptor instead.
func (Status) EnumDescriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{1}
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{0}
}

type KeyName struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *KeyName) Reset() {
	*x = KeyName{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyName) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyName) ProtoMessage() {}

func (x *KeyName) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyName.ProtoReflect.Descriptor instead.
func (*KeyName) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{1}
}

func (x *KeyName) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type EncryptionType `protobuf:"varint,2,opt,name=type,proto3,enum=EncryptionType" json:"type,omitempty"`
}

func (x *Key) Reset() {
	*x = Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Key) ProtoMessage() {}

func (x *Key) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Key.ProtoReflect.Descriptor instead.
func (*Key) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{2}
}

func (x *Key) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Key) GetType() EncryptionType {
	if x != nil {
		return x.Type
	}
	return EncryptionType_AES256_GCM96
}

type KeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status  Status `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Key     *Key   `protobuf:"bytes,3,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *KeyResponse) Reset() {
	*x = KeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyResponse) ProtoMessage() {}

func (x *KeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyResponse.ProtoReflect.Descriptor instead.
func (*KeyResponse) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{3}
}

func (x *KeyResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *KeyResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *KeyResponse) GetKey() *Key {
	if x != nil {
		return x.Key
	}
	return nil
}

type KeyListResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status  Status `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Keys    []*Key `protobuf:"bytes,3,rep,name=keys,proto3" json:"keys,omitempty"`
}

func (x *KeyListResponse) Reset() {
	*x = KeyListResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyListResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyListResponse) ProtoMessage() {}

func (x *KeyListResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyListResponse.ProtoReflect.Descriptor instead.
func (*KeyListResponse) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{4}
}

func (x *KeyListResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *KeyListResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *KeyListResponse) GetKeys() []*Key {
	if x != nil {
		return x.Keys
	}
	return nil
}

type EncryptRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyName    string `protobuf:"bytes,1,opt,name=keyName,proto3" json:"keyName,omitempty"`
	PlainText  string `protobuf:"bytes,2,opt,name=plainText,proto3" json:"plainText,omitempty"`
	Nonce      string `protobuf:"bytes,3,opt,name=nonce,proto3" json:"nonce,omitempty"`
	KeyVersion int64  `protobuf:"varint,4,opt,name=keyVersion,proto3" json:"keyVersion,omitempty"`
}

func (x *EncryptRequest) Reset() {
	*x = EncryptRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptRequest) ProtoMessage() {}

func (x *EncryptRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptRequest.ProtoReflect.Descriptor instead.
func (*EncryptRequest) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{5}
}

func (x *EncryptRequest) GetKeyName() string {
	if x != nil {
		return x.KeyName
	}
	return ""
}

func (x *EncryptRequest) GetPlainText() string {
	if x != nil {
		return x.PlainText
	}
	return ""
}

func (x *EncryptRequest) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

func (x *EncryptRequest) GetKeyVersion() int64 {
	if x != nil {
		return x.KeyVersion
	}
	return 0
}

type DecryptRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyName    string `protobuf:"bytes,1,opt,name=keyName,proto3" json:"keyName,omitempty"`
	Ciphertext string `protobuf:"bytes,2,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	Nonce      string `protobuf:"bytes,3,opt,name=nonce,proto3" json:"nonce,omitempty"`
	KeyVersion int64  `protobuf:"varint,4,opt,name=keyVersion,proto3" json:"keyVersion,omitempty"`
}

func (x *DecryptRequest) Reset() {
	*x = DecryptRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecryptRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecryptRequest) ProtoMessage() {}

func (x *DecryptRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecryptRequest.ProtoReflect.Descriptor instead.
func (*DecryptRequest) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{6}
}

func (x *DecryptRequest) GetKeyName() string {
	if x != nil {
		return x.KeyName
	}
	return ""
}

func (x *DecryptRequest) GetCiphertext() string {
	if x != nil {
		return x.Ciphertext
	}
	return ""
}

func (x *DecryptRequest) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

func (x *DecryptRequest) GetKeyVersion() int64 {
	if x != nil {
		return x.KeyVersion
	}
	return 0
}

type CryptoResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result string `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CryptoResult) Reset() {
	*x = CryptoResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CryptoResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CryptoResult) ProtoMessage() {}

func (x *CryptoResult) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CryptoResult.ProtoReflect.Descriptor instead.
func (*CryptoResult) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{7}
}

func (x *CryptoResult) GetResult() string {
	if x != nil {
		return x.Result
	}
	return ""
}

type HashRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algorithm string `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Input     string `protobuf:"bytes,2,opt,name=input,proto3" json:"input,omitempty"`
	Format    string `protobuf:"bytes,3,opt,name=format,proto3" json:"format,omitempty"`
}

func (x *HashRequest) Reset() {
	*x = HashRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HashRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HashRequest) ProtoMessage() {}

func (x *HashRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HashRequest.ProtoReflect.Descriptor instead.
func (*HashRequest) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{8}
}

func (x *HashRequest) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

func (x *HashRequest) GetInput() string {
	if x != nil {
		return x.Input
	}
	return ""
}

func (x *HashRequest) GetFormat() string {
	if x != nil {
		return x.Format
	}
	return ""
}

type HashResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result string `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *HashResponse) Reset() {
	*x = HashResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HashResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HashResponse) ProtoMessage() {}

func (x *HashResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HashResponse.ProtoReflect.Descriptor instead.
func (*HashResponse) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{9}
}

func (x *HashResponse) GetResult() string {
	if x != nil {
		return x.Result
	}
	return ""
}

type HMACRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyName    string `protobuf:"bytes,1,opt,name=keyName,proto3" json:"keyName,omitempty"`
	KeyVersion int64  `protobuf:"varint,2,opt,name=keyVersion,proto3" json:"keyVersion,omitempty"`
	Algorithm  string `protobuf:"bytes,3,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Input      string `protobuf:"bytes,4,opt,name=input,proto3" json:"input,omitempty"`
}

func (x *HMACRequest) Reset() {
	*x = HMACRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HMACRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HMACRequest) ProtoMessage() {}

func (x *HMACRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HMACRequest.ProtoReflect.Descriptor instead.
func (*HMACRequest) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{10}
}

func (x *HMACRequest) GetKeyName() string {
	if x != nil {
		return x.KeyName
	}
	return ""
}

func (x *HMACRequest) GetKeyVersion() int64 {
	if x != nil {
		return x.KeyVersion
	}
	return 0
}

func (x *HMACRequest) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

func (x *HMACRequest) GetInput() string {
	if x != nil {
		return x.Input
	}
	return ""
}

type HMACResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result string `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *HMACResponse) Reset() {
	*x = HMACResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_structs_structs_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HMACResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HMACResponse) ProtoMessage() {}

func (x *HMACResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_structs_structs_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HMACResponse.ProtoReflect.Descriptor instead.
func (*HMACResponse) Descriptor() ([]byte, []int) {
	return file_pkg_structs_structs_proto_rawDescGZIP(), []int{11}
}

func (x *HMACResponse) GetResult() string {
	if x != nil {
		return x.Result
	}
	return ""
}

var File_pkg_structs_structs_proto protoreflect.FileDescriptor

var file_pkg_structs_structs_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x6b, 0x67, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x73, 0x2f, 0x73, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x07, 0x0a, 0x05, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x22, 0x1d, 0x0a, 0x07, 0x4b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x22, 0x3e, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x23,
	0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x45,
	0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x22, 0x60, 0x0a, 0x0b, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1f, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x07, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x16, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x04, 0x2e, 0x4b, 0x65, 0x79,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x22, 0x66, 0x0a, 0x0f, 0x4b, 0x65, 0x79, 0x4c, 0x69, 0x73, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x07, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x18, 0x0a, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x04, 0x2e, 0x4b, 0x65, 0x79, 0x52, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x22, 0x7e, 0x0a,
	0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x18, 0x0a, 0x07, 0x6b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x6b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x6c, 0x61,
	0x69, 0x6e, 0x54, 0x65, 0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x6c,
	0x61, 0x69, 0x6e, 0x54, 0x65, 0x78, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x1e, 0x0a,
	0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x80, 0x01,
	0x0a, 0x0e, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x6b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69,
	0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f,
	0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
	0x12, 0x1e, 0x0a, 0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x22, 0x26, 0x0a, 0x0c, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x59, 0x0a, 0x0b, 0x48, 0x61, 0x73, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f,
	0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x66, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x22, 0x26, 0x0a, 0x0c, 0x48, 0x61, 0x73, 0x68, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x7b, 0x0a, 0x0b, 0x48,
	0x4d, 0x41, 0x43, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x6b, 0x65,
	0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6b, 0x65, 0x79,
	0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x26, 0x0a, 0x0c, 0x48, 0x4d, 0x41, 0x43,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x2a, 0x39, 0x0a, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x10, 0x0a, 0x0c, 0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x5f, 0x47, 0x43, 0x4d,
	0x39, 0x36, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x43, 0x48, 0x41, 0x43, 0x48, 0x41, 0x32, 0x30,
	0x5f, 0x50, 0x4f, 0x4c, 0x59, 0x31, 0x33, 0x30, 0x35, 0x10, 0x01, 0x2a, 0x2d, 0x0a, 0x06, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e,
	0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x10, 0x01, 0x12,
	0x09, 0x0a, 0x05, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x02, 0x32, 0xc3, 0x02, 0x0a, 0x0a, 0x45,
	0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x09, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x04, 0x2e, 0x4b, 0x65, 0x79, 0x1a, 0x0c, 0x2e, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x21, 0x0a, 0x07, 0x52, 0x65,
	0x61, 0x64, 0x4b, 0x65, 0x79, 0x12, 0x08, 0x2e, 0x4b, 0x65, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x1a,
	0x0c, 0x2e, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x23, 0x0a,
	0x09, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x08, 0x2e, 0x4b, 0x65, 0x79,
	0x4e, 0x61, 0x6d, 0x65, 0x1a, 0x0c, 0x2e, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x24, 0x0a, 0x08, 0x4c, 0x69, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x06,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x10, 0x2e, 0x4b, 0x65, 0x79, 0x4c, 0x69, 0x73, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x29, 0x0a, 0x07, 0x45, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x12, 0x0f, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x0d, 0x2e, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x52, 0x65, 0x73,
	0x75, 0x6c, 0x74, 0x12, 0x29, 0x0a, 0x07, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x12, 0x0f,
	0x2e, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x0d, 0x2e, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x23,
	0x0a, 0x04, 0x48, 0x61, 0x73, 0x68, 0x12, 0x0c, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x0d, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x0c, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x48,
	0x4d, 0x41, 0x43, 0x12, 0x0c, 0x2e, 0x48, 0x4d, 0x41, 0x43, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x0d, 0x2e, 0x48, 0x4d, 0x41, 0x43, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x0d, 0x5a, 0x0b, 0x70, 0x6b, 0x67, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x73, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_structs_structs_proto_rawDescOnce sync.Once
	file_pkg_structs_structs_proto_rawDescData = file_pkg_structs_structs_proto_rawDesc
)

func file_pkg_structs_structs_proto_rawDescGZIP() []byte {
	file_pkg_structs_structs_proto_rawDescOnce.Do(func() {
		file_pkg_structs_structs_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_structs_structs_proto_rawDescData)
	})
	return file_pkg_structs_structs_proto_rawDescData
}

var file_pkg_structs_structs_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_pkg_structs_structs_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_pkg_structs_structs_proto_goTypes = []interface{}{
	(EncryptionType)(0),     // 0: EncryptionType
	(Status)(0),             // 1: Status
	(*Empty)(nil),           // 2: Empty
	(*KeyName)(nil),         // 3: KeyName
	(*Key)(nil),             // 4: Key
	(*KeyResponse)(nil),     // 5: KeyResponse
	(*KeyListResponse)(nil), // 6: KeyListResponse
	(*EncryptRequest)(nil),  // 7: EncryptRequest
	(*DecryptRequest)(nil),  // 8: DecryptRequest
	(*CryptoResult)(nil),    // 9: CryptoResult
	(*HashRequest)(nil),     // 10: HashRequest
	(*HashResponse)(nil),    // 11: HashResponse
	(*HMACRequest)(nil),     // 12: HMACRequest
	(*HMACResponse)(nil),    // 13: HMACResponse
}
var file_pkg_structs_structs_proto_depIdxs = []int32{
	0,  // 0: Key.type:type_name -> EncryptionType
	1,  // 1: KeyResponse.status:type_name -> Status
	4,  // 2: KeyResponse.key:type_name -> Key
	1,  // 3: KeyListResponse.status:type_name -> Status
	4,  // 4: KeyListResponse.keys:type_name -> Key
	4,  // 5: Encryption.CreateKey:input_type -> Key
	3,  // 6: Encryption.ReadKey:input_type -> KeyName
	3,  // 7: Encryption.DeleteKey:input_type -> KeyName
	2,  // 8: Encryption.ListKeys:input_type -> Empty
	7,  // 9: Encryption.Encrypt:input_type -> EncryptRequest
	8,  // 10: Encryption.Decrypt:input_type -> DecryptRequest
	10, // 11: Encryption.Hash:input_type -> HashRequest
	12, // 12: Encryption.GenerateHMAC:input_type -> HMACRequest
	5,  // 13: Encryption.CreateKey:output_type -> KeyResponse
	5,  // 14: Encryption.ReadKey:output_type -> KeyResponse
	5,  // 15: Encryption.DeleteKey:output_type -> KeyResponse
	6,  // 16: Encryption.ListKeys:output_type -> KeyListResponse
	9,  // 17: Encryption.Encrypt:output_type -> CryptoResult
	9,  // 18: Encryption.Decrypt:output_type -> CryptoResult
	11, // 19: Encryption.Hash:output_type -> HashResponse
	13, // 20: Encryption.GenerateHMAC:output_type -> HMACResponse
	13, // [13:21] is the sub-list for method output_type
	5,  // [5:13] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_pkg_structs_structs_proto_init() }
func file_pkg_structs_structs_proto_init() {
	if File_pkg_structs_structs_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_structs_structs_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyName); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Key); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyListResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecryptRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CryptoResult); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HashRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HashResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HMACRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_structs_structs_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HMACResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_structs_structs_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_structs_structs_proto_goTypes,
		DependencyIndexes: file_pkg_structs_structs_proto_depIdxs,
		EnumInfos:         file_pkg_structs_structs_proto_enumTypes,
		MessageInfos:      file_pkg_structs_structs_proto_msgTypes,
	}.Build()
	File_pkg_structs_structs_proto = out.File
	file_pkg_structs_structs_proto_rawDesc = nil
	file_pkg_structs_structs_proto_goTypes = nil
	file_pkg_structs_structs_proto_depIdxs = nil
}
