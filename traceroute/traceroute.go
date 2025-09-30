package traceroute

import (
	"context"

	"github.com/DataDog/datadog-traceroute/result"
)

type Traceroute struct {
}

func NewTraceroute() *Traceroute {
	return &Traceroute{}
}

func (t Traceroute) RunTraceroute(ctx context.Context, params TracerouteParams) (*result.Results, error) {
	return RunTraceroute(ctx, params)
}
