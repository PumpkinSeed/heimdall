package transit

import (
	"context"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

func (t Transit) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error){
	return nil, nil
}

func (t Transit) VerifySign(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	return nil,nil
}
