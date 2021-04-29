package healthcheck

import (
	"context"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	log "github.com/sirupsen/logrus"
)

const (
	StatusFailed = "FAILED"
	StatusOK     = "OK"

	msgInitializationError = "Initialization error"
	msgNotInitialized      = "Not initialized"
	msgHealthy             = "healthy"
)

type Healthcheck struct {
	u *unseal.Unseal
}

func New(u *unseal.Unseal) Healthcheck {
	return Healthcheck{
		u: u,
	}
}

func (hc Healthcheck) Check(ctx context.Context) *structs.HealthResponse {
	init, err := hc.u.SecurityBarrier.Initialized(ctx)
	if err != nil {
		log.Errorf("initialization error: %v", err)

		return &structs.HealthResponse{
			Status:  StatusFailed,
			Message: msgInitializationError,
		}
	}

	if !init {
		return &structs.HealthResponse{
			Status:  StatusFailed,
			Message: msgNotInitialized,
		}
	}

	return &structs.HealthResponse{
		Status:  StatusOK,
		Message: msgHealthy,
	}
}
