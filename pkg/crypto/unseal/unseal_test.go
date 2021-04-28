package unseal

import (
	"context"
	"testing"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/mount"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
)

var expectedMasterKey = []byte{189, 121, 77, 142, 213, 195, 183, 143, 119, 147, 168, 188, 242, 216, 180,
	245, 110, 118, 183, 203, 72, 121, 94, 174, 222, 164, 209, 240, 156, 246, 22, 109}

func TestUnseal_Unseal(t *testing.T) {
	ctx := context.Background()

	m := mockBackend{}
	m.On("Get", ctx, BarrierKeysPath).Return(&physical.Entry{
		Key: BarrierKeysPath,
		Value: []byte{10, 76, 108, 24, 51, 243, 113, 43, 241, 157, 113, 182, 209, 44, 148, 160,
			176, 172, 20, 134, 52, 177, 100, 38, 52, 19, 25, 126, 204, 240, 88, 85, 29, 0, 41, 231,
			3, 163, 213, 89, 142, 37, 27, 111, 45, 189, 147, 225, 9, 241, 31, 197, 193, 3, 188, 254,
			188, 133, 52, 110, 233, 253, 143, 146, 127, 164, 248, 231, 152, 209, 153, 211, 217, 244, 82, 217, 35, 6, 42, 0},
		SealWrap:  false,
		ValueHash: nil,
	}, nil)

	u := Unseal{Threshold: 3, Backend: &m}

	var ok bool
	for _, key := range [][]byte{
		[]byte("v0cY5GRpYaEmthQslOCaoT9x6WCy0SaVZ0+9di26zQ3z"),
		[]byte("JHNmbf2O/EIbPZesPNC7cIGDPyZMY72TYI7nfjlvgvOp"),
		[]byte("Lm78dm+K585VkFuFBRyOWPQBNV/9QE7X7fV9Uot0Hc0z")} {

		var err error
		ok, err = u.Unseal(ctx, string(key))
		assert.Nil(t, err)
	}
	assert.True(t, ok)
	assert.Equal(t, expectedMasterKey, u.masterKey)
	assert.Equal(t, [][]byte{}, u.tempKeys)
}

func TestUnseal_Keyring(t *testing.T) {
	ctx := context.Background()

	m := mockBackend{}
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

	u := Unseal{Threshold: 3,
		masterKey: expectedMasterKey,
		Backend:   &m,
	}

	err := u.Keyring(ctx)
	assert.Nil(t, err)
	assert.NotNil(t, u.keyring)
	assert.Equal(t, expectedMasterKey, u.keyring.MasterKey())
	assert.Equal(t, uint32(1), u.keyring.ActiveTerm())
}

func TestUnseal_Mount(t *testing.T) {
	ctx := context.Background()
	m := mockBackend{}
	m.On("Get", ctx, mount.CorePath).Return(&physical.Entry{
		Key: mount.CorePath,
		Value: []byte{0, 0, 0, 1, 2, 70, 161, 218, 39, 34, 150, 80, 78, 7, 49, 141, 159, 36, 216, 112, 179, 59, 207,
			72, 44, 40, 89, 8, 114, 219, 129, 7, 237, 248, 194, 26, 235, 10, 13, 134, 32, 105, 225, 149, 7, 104, 81,
			140, 87, 188, 68, 66, 20, 217, 248, 236, 145, 203, 234, 145, 101, 221, 47, 19, 193, 6, 96, 158, 129, 116,
			22, 215, 238, 227, 32, 97, 80, 104, 57, 32, 22, 191, 62, 222, 23, 85, 121, 33, 1, 137, 251, 74, 185, 74,
			53, 91, 191, 69, 165, 149, 136, 20, 130, 27, 57, 33, 144, 208, 151, 48, 231, 186, 163, 42, 109, 135, 19,
			118, 189, 241, 158, 222, 93, 134, 229, 139, 202, 30, 12, 165, 71, 217, 157, 171, 132, 113, 94, 165, 6,
			35, 164, 198, 98, 150, 212, 200, 96, 155, 130, 194, 220, 86, 83, 60, 24, 130, 112, 206, 89, 173, 124, 58,
			112, 75, 240, 72, 34, 132, 18, 91, 233, 219, 163, 250, 63, 13, 183, 64, 78, 155, 126, 235, 218, 170, 221,
			203, 138, 211, 144, 50, 185, 196, 185, 143, 205, 49, 130, 158, 56, 64, 88, 19, 206, 191, 199, 109, 192,
			242, 201, 21, 108, 224, 101, 171, 123, 224, 149, 47, 147, 14, 57, 37, 16, 120, 135, 243, 253, 85, 82, 126,
			94, 153, 204, 248, 45, 207, 112, 17, 226, 161, 158, 45, 157, 230, 166, 161, 33, 173, 92, 143, 136, 17, 95,
			151, 180, 114, 185, 42, 21, 208, 102, 75, 117, 94, 117, 133, 250, 124, 11, 14, 84, 58, 163, 36, 110, 87,
			106, 253, 9, 173, 22, 114, 147, 69, 239, 87, 103, 66, 98, 168, 184, 179, 137, 253, 152, 3, 246, 235, 114,
			56, 55, 34, 66, 208, 188, 180, 7, 132, 234, 117, 211, 250, 195, 106, 12, 244, 111, 200, 18, 149, 190, 121,
			222, 221, 144, 29, 202, 88, 88, 112, 25, 216, 129, 1, 103, 206, 198, 214, 13, 6, 191, 95, 130, 156, 228,
			252, 58, 106, 137, 157, 221, 47, 179, 233, 135, 170, 16, 140, 145, 36, 206, 123, 69, 252, 151, 184, 215,
			160, 84, 111, 20, 206, 124, 23, 41, 229, 112, 45, 239, 114, 254, 17, 96, 186, 246, 170, 252, 138, 242, 33,
			54, 254, 158, 91, 126, 215, 110, 99, 137, 251, 153, 50, 220, 210, 240, 230, 26, 17, 211, 100, 75, 152, 232,
			216, 55, 138, 70, 244, 166, 164, 240, 127, 189, 231, 106, 77, 147, 180, 160, 224, 0, 175, 93, 100, 199, 216,
			70, 70, 235, 248, 97, 201, 253, 179, 23, 52, 243, 27, 231, 149, 0, 84, 67, 224, 50, 54, 215, 252, 190, 25,
			179, 200, 136, 33, 244, 20, 190, 94, 123, 52, 228, 183, 180, 175, 202, 185, 45, 243, 26, 170, 1, 26, 180, 128,
			167, 232, 207, 214, 88, 10, 33, 76, 105, 195, 53, 60, 11, 17, 41, 74, 188, 37, 172, 199, 92, 233, 185, 186, 169,
		},
	}, nil)

	u := Unseal{
		masterKey: expectedMasterKey,
		keyring:   givenKeyring(),
		Threshold: 3,
		Backend:   &m,
	}

	_, err := u.Mount(ctx)
	assert.Nil(t, err)
}

func givenKeyring() *vault.Keyring {
	kr := vault.NewKeyring()
	kr, _ = kr.AddKey(&vault.Key{
		Term:    1,
		Version: 1,
		Value: []byte{223, 143, 250, 174, 49, 108, 146, 90, 17, 42, 200, 89, 208, 40, 15,
			153, 39, 196, 168, 206, 47, 93, 59, 150, 169, 81, 88, 100, 31, 130, 78, 33},
	})
	return kr
}
