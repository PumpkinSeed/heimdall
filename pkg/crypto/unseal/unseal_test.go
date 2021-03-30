package unseal

import (
	"context"
	"testing"

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
	m.On("Get", ctx, storedBarrierKeysPath).Return(&physical.Entry{
		Key: storedBarrierKeysPath,
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
