package gin

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockServer struct {
	listenErr   error
	shutdownErr error
}

func (m *mockServer) ListenAndServe() error {
	return m.listenErr
}

func (m *mockServer) Shutdown(_ context.Context) error {
	return m.shutdownErr
}

func TestHttpServer_NewWithNilServerReturnsError(t *testing.T) {
	t.Parallel()

	srv, err := NewHttpServer(nil)
	require.Nil(t, srv)
	require.Equal(t, ErrNilHttpServer, err)
}

func TestHttpServer_CloseReturnsNilOnSuccess(t *testing.T) {
	t.Parallel()

	srv, err := NewHttpServer(&mockServer{})
	require.Nil(t, err)
	require.Nil(t, srv.Close())
}

func TestHttpServer_CloseReturnsErrorOnShutdownFailure(t *testing.T) {
	t.Parallel()

	shutdownErr := errors.New("shutdown failed")
	srv, err := NewHttpServer(&mockServer{shutdownErr: shutdownErr})
	require.Nil(t, err)

	closeErr := srv.Close()
	require.Equal(t, shutdownErr, closeErr)
}

func TestHttpServer_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var srv *httpServer
	require.True(t, srv.IsInterfaceNil())

	real, _ := NewHttpServer(&mockServer{})
	require.False(t, real.IsInterfaceNil())
}
