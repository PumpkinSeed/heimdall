package unseal

import (
	"context"
	"testing"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var expectedMasterKey = []byte{189, 121, 77, 142, 213, 195, 183, 143, 119, 147, 168, 188, 242, 216, 180,
	245, 110, 118, 183, 203, 72, 121, 94, 174, 222, 164, 209, 240, 156, 246, 22, 109}

type mockBackend struct {
	mock.Mock
}

func (m mockBackend) Put(ctx context.Context, entry *physical.Entry) error {
	panic("implement me")
}

func (m mockBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*physical.Entry), args.Error(1)
}

func (m mockBackend) Delete(ctx context.Context, key string) error {
	panic("implement me")
}

func (m mockBackend) List(ctx context.Context, prefix string) ([]string, error) {
	panic("implement me")
}

func TestUnseal_Unseal(t *testing.T) {
	u := unseal{}

	ctx := context.Background()

	m := &mockBackend{}
	m.On("Get", ctx, BarrierKeysPath).Return(&physical.Entry{
		Key: BarrierKeysPath,
		Value: []byte{10, 76, 108, 24, 51, 243, 113, 43, 241, 157, 113, 182, 209, 44, 148, 160,
			176, 172, 20, 134, 52, 177, 100, 38, 52, 19, 25, 126, 204, 240, 88, 85, 29, 0, 41, 231,
			3, 163, 213, 89, 142, 37, 27, 111, 45, 189, 147, 225, 9, 241, 31, 197, 193, 3, 188, 254,
			188, 133, 52, 110, 233, 253, 143, 146, 127, 164, 248, 231, 152, 209, 153, 211, 217, 244, 82, 217, 35, 6, 42, 0},
		SealWrap:  false,
		ValueHash: nil,
	}, nil)

	var ok bool
	for _, key := range [][]byte{
		[]byte("v0cY5GRpYaEmthQslOCaoT9x6WCy0SaVZ0+9di26zQ3z"),
		[]byte("JHNmbf2O/EIbPZesPNC7cIGDPyZMY72TYI7nfjlvgvOp"),
		[]byte("Lm78dm+K585VkFuFBRyOWPQBNV/9QE7X7fV9Uot0Hc0z")} {

		var err error
		ok, err = u.Unseal(ctx, m, string(key))
		assert.Nil(t, err)
	}
	assert.True(t, ok)
	assert.Equal(t, expectedMasterKey, u.masterKey)
}

func TestUnseal_Keyring(t *testing.T) {
	u := unseal{masterKey: expectedMasterKey}

	ctx := context.Background()

	m := &mockBackend{}
	m.On("Get", ctx, keyring.Path).Return(&physical.Entry{
		Key: keyring.Path,
		Value: []byte{0, 0, 0, 1, 2, 48, 130, 173, 191, 53, 17, 230, 160, 131, 197, 61, 98, 152, 231, 57, 161,
			241, 60, 79, 37, 5, 194, 29, 201, 95, 12, 141, 32, 84, 180, 92, 163, 195, 169, 112, 193, 56, 85,
			229, 196, 19, 5, 69, 25, 206, 109, 120, 68, 244, 172, 80, 4, 133, 187, 171, 2, 49, 232, 25, 24, 199,
			143, 100, 74, 1, 39, 70, 234, 65, 30, 226, 53, 47, 240, 209, 73, 210, 144, 55, 14, 104, 111, 35, 117,
			245, 121, 45, 106, 54, 229, 202, 90, 0, 189, 37, 124, 243, 210, 2, 137, 121, 189, 213, 11, 65, 233, 234,
			93, 204, 151, 172, 36, 15, 31, 178, 78, 239, 244, 11, 59, 20, 146, 57, 223, 7, 129, 53, 188, 119, 211, 43,
			216, 81, 40, 20, 171, 98, 162, 51, 33, 54, 28, 184, 234, 188, 236, 76, 89, 85, 192, 145, 224, 79, 142, 158,
			71, 165, 27, 57, 110, 112, 201, 21, 21, 192, 18, 9, 154, 199, 151, 182, 17, 140, 50, 218, 82, 229, 196, 210,
			183, 15, 200, 127, 201, 20, 60, 42, 116, 126, 72, 94, 67, 134, 77, 56, 93, 216, 229, 10, 179, 12, 122, 168,
			11, 42, 188, 183, 209, 39, 48, 108, 180, 93, 84, 225, 103, 43, 176, 156, 244},
	}, nil)

	err := u.Keyring(ctx, m)
	assert.Nil(t, err)
	assert.NotNil(t, u.keyring)
}
