// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	k8skmsv2 "k8s.io/kms/apis/v2"
)

// stubProvider satisfies providers.Provider without touching a token: these tests are about how
// the gRPC server is assembled, not about what the provider does once a call reaches it.
type stubProvider struct {
	k8skmsv2.UnimplementedKeyManagementServiceServer
}

func (s *stubProvider) UnaryInterceptor(
	ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (interface{}, error) {
	return handler(ctx, req)
}

// TestNewKMSGRPCServer_DoesNotRegisterReflection pins the removal of server reflection.
//
// Reflection publishes the service schema to any client that can open the socket. Nothing in the
// product needs it — kube-apiserver is compiled against the KMS v2 protobuf, and the e2e suite
// passes `grpcurl -proto` — so registering it only helped a local process discover what to call.
// Registration leaves no trace at runtime other than the extra service, which is what this
// asserts.
func TestNewKMSGRPCServer_DoesNotRegisterReflection(t *testing.T) {
	gs := newKMSGRPCServer(&stubProvider{})
	defer gs.Stop()

	services := gs.GetServiceInfo()

	require.Contains(t, services, "v2.KeyManagementService",
		"the KMS v2 service must still be registered")
	for name := range services {
		assert.NotContains(t, name, "ServerReflection",
			"server reflection must not be registered: %s", name)
	}
	assert.Len(t, services, 1, "only the KMS v2 service should be served: %v", services)
}

// fakeServerStream is the minimum grpc.ServerStream needed to invoke unknownServiceHandler.
// Its context carries no gRPC method, so MethodFromServerStream reports none, which is the
// branch that used to be least likely to be exercised.
type fakeServerStream struct{ ctx context.Context }

func (f *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeServerStream) SetTrailer(metadata.MD)       {}
func (f *fakeServerStream) Context() context.Context     { return f.ctx }
func (f *fakeServerStream) SendMsg(interface{}) error    { return nil }
func (f *fakeServerStream) RecvMsg(interface{}) error    { return nil }

// TestUnknownServiceHandler_ReturnsUnimplemented pins the handler's contract.
//
// It previously returned nil, which reports success for a call that ran nothing: a client
// invoking a method this plugin does not implement received an empty response and no error, and
// had to infer the failure. The handler must answer with a status instead, and gRPC defines
// Unimplemented for exactly this case.
func TestUnknownServiceHandler_ReturnsUnimplemented(t *testing.T) {
	err := unknownServiceHandler(nil, &fakeServerStream{ctx: context.Background()})

	require.Error(t, err, "an unimplemented method must not be answered with success")
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
