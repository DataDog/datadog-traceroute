package traceroute

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
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
