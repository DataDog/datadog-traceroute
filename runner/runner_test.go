package runner

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
	"github.com/stretchr/testify/require"
)

func neverCalled(t *testing.T) tracerouteImpl {
	return func() (*result.Results, error) {
		t.Fatal("should not call this")
		return nil, fmt.Errorf("should not call this")
	}
}

func TestTCPFallback(t *testing.T) {
	dummySyn := &result.Results{}
	dummySack := &result.Results{}
	dummyErr := fmt.Errorf("test error")
	dummySackUnsupportedErr := &sack.NotSupportedError{
		Err: fmt.Errorf("dummy sack unsupported"),
	}
	dummySynSocket := &result.Results{}

	t.Run("force SYN", func(t *testing.T) {
		doSyn := func() (*result.Results, error) {
			return dummySyn, nil
		}
		doSack := neverCalled(t)
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(common.TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.Results, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(common.TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SACK", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.Results, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(common.TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.Results, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(common.TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - only running sack", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.Results, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(common.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.Results, error) {
			return nil, dummyErr
		}
		// error case (sack encounters a fatal error and does not fall back to SYN)
		results, err = performTCPFallback(common.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.ErrorIs(t, err, dummyErr)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - fallback case", func(t *testing.T) {
		doSyn := func() (*result.Results, error) {
			return dummySyn, nil
		}
		doSack := func() (*result.Results, error) {
			// cause a fallback because the target doesn't support SACK
			return nil, dummySackUnsupportedErr
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(common.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.Results, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(common.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SYN socket", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := neverCalled(t)
		doSynSocket := func() (*result.Results, error) {
			return dummySynSocket, nil
		}
		// success case
		results, err := performTCPFallback(common.TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySynSocket, results)

		doSynSocket = func() (*result.Results, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(common.TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})
}
