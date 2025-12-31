package traceroute

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func neverCalled(t *testing.T) tracerouteImpl {
	return func() (*result.TracerouteRun, error) {
		t.Fatal("should not call this")
		return nil, fmt.Errorf("should not call this")
	}
}

func TestTCPFallback(t *testing.T) {
	dummySyn := &result.TracerouteRun{}
	dummySack := &result.TracerouteRun{}
	dummyErr := fmt.Errorf("test error")
	dummySackUnsupportedErr := &sack.NotSupportedError{
		Err: fmt.Errorf("dummy sack unsupported"),
	}
	dummySynSocket := &result.TracerouteRun{}

	t.Run("force SYN", func(t *testing.T) {
		doSyn := func() (*result.TracerouteRun, error) {
			return dummySyn, nil
		}
		doSack := neverCalled(t)
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SACK", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.TracerouteRun, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - only running sack", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.TracerouteRun, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case (sack encounters a fatal error and does not fall back to SYN)
		results, err = performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.ErrorIs(t, err, dummyErr)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - fallback case", func(t *testing.T) {
		doSyn := func() (*result.TracerouteRun, error) {
			return dummySyn, nil
		}
		doSack := func() (*result.TracerouteRun, error) {
			// cause a fallback because the target doesn't support SACK
			return nil, dummySackUnsupportedErr
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SYN socket", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := neverCalled(t)
		doSynSocket := func() (*result.TracerouteRun, error) {
			return dummySynSocket, nil
		}
		// success case
		results, err := performTCPFallback(TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySynSocket, results)

		doSynSocket = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})
}

func TestParseTarget(t *testing.T) {
	t.Run("IPv4 literal", func(t *testing.T) {
		addrPort, err := parseTarget("192.168.1.1", 80, false)
		require.NoError(t, err)
		assert.True(t, addrPort.Addr().Is4(), "should be IPv4")
		assert.Equal(t, "192.168.1.1", addrPort.Addr().String())
		assert.Equal(t, uint16(80), addrPort.Port())
	})

	t.Run("IPv6 literal", func(t *testing.T) {
		addrPort, err := parseTarget("2001:db8::1", 443, true)
		require.NoError(t, err)
		assert.True(t, addrPort.Addr().Is6(), "should be IPv6")
		assert.Equal(t, "2001:db8::1", addrPort.Addr().String())
		assert.Equal(t, uint16(443), addrPort.Port())
	})

	t.Run("IPv6 literal bracketed with port", func(t *testing.T) {
		addrPort, err := parseTarget("[2001:db8::1]:8080", 80, true)
		require.NoError(t, err)
		assert.True(t, addrPort.Addr().Is6(), "should be IPv6")
		assert.Equal(t, "2001:db8::1", addrPort.Addr().String())
		assert.Equal(t, uint16(8080), addrPort.Port())
	})

	t.Run("IPv4 with explicit port", func(t *testing.T) {
		addrPort, err := parseTarget("10.0.0.1:9000", 80, false)
		require.NoError(t, err)
		assert.True(t, addrPort.Addr().Is4(), "should be IPv4")
		assert.Equal(t, "10.0.0.1", addrPort.Addr().String())
		assert.Equal(t, uint16(9000), addrPort.Port())
	})
}
