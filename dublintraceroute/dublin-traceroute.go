/* SPDX-License-Identifier: BSD-2-Clause */

package dublintraceroute

import (
	"time"

	payload "github.com/AlexandreYang/datadog-traceroute/dublintraceroute/netpath_payload"
)

// default values and constants
const (
	DefaultReadTimeout = time.Millisecond * 3000
)

// DublinTraceroute is the common interface that every Dublin Traceroute
// probe type has to implement
type DublinTraceroute interface {
	Validate() error
	Traceroute() (*payload.NetworkPath, error)
}
