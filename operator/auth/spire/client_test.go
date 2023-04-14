// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"fmt"
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type mockEntryClient struct {
	ListEntriesFunc      func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error)
	BatchCreateEntryFunc func(ctx context.Context, in *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error)
	BatchUpdateEntryFunc func(ctx context.Context, in *entryv1.BatchUpdateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error)
	BatchDeleteEntryFunc func(ctx context.Context, in *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error)
}

func (m mockEntryClient) CountEntries(ctx context.Context, in *entryv1.CountEntriesRequest, opts ...grpc.CallOption) (*entryv1.CountEntriesResponse, error) {
	panic("implement me")
}

func (m mockEntryClient) ListEntries(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	return m.ListEntriesFunc(ctx, in, opts...)
}

func (m mockEntryClient) GetEntry(ctx context.Context, in *entryv1.GetEntryRequest, opts ...grpc.CallOption) (*types.Entry, error) {
	panic("implement me")
}

func (m mockEntryClient) BatchCreateEntry(ctx context.Context, in *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
	return m.BatchCreateEntryFunc(ctx, in, opts...)
}

func (m mockEntryClient) BatchUpdateEntry(ctx context.Context, in *entryv1.BatchUpdateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
	return m.BatchUpdateEntryFunc(ctx, in, opts...)
}

func (m mockEntryClient) BatchDeleteEntry(ctx context.Context, in *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	return m.BatchDeleteEntryFunc(ctx, in, opts...)
}

func (m mockEntryClient) GetAuthorizedEntries(ctx context.Context, in *entryv1.GetAuthorizedEntriesRequest, opts ...grpc.CallOption) (*entryv1.GetAuthorizedEntriesResponse, error) {
	panic("implement me")
}

func TestClient_Upsert(t *testing.T) {
	cfg := ClientConfig{
		SpiffeTrustDomain: "dummy.trusted.domain",
	}
	type fields struct {
		entry entryv1.EntryClient
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "client not initialized",
			wantErr: true,
		},
		{
			name: "unable to list entry due to unknown error",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return nil, fmt.Errorf("something is wrong")
					},
				},
			},
			wantErr: true,
		},
		{
			name: "entry does not exist with not found error",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return nil, fmt.Errorf("NotFound")
					},
					BatchCreateEntryFunc: func(ctx context.Context, in *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
						require.ElementsMatch(t, in.Entries, []*types.Entry{
							{
								SpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								Selectors: defaultSelectors,
							},
						})
						return &entryv1.BatchCreateEntryResponse{}, nil
					},
				},
			},
		},
		{
			name: "entry exists",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return &entryv1.ListEntriesResponse{
							Entries: []*types.Entry{{}},
						}, nil
					},
					BatchUpdateEntryFunc: func(ctx context.Context, in *entryv1.BatchUpdateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
						require.ElementsMatch(t, in.Entries, []*types.Entry{
							{
								SpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								Selectors: defaultSelectors,
							},
						})
						return &entryv1.BatchUpdateEntryResponse{}, nil
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				cfg:   cfg,
				entry: tt.fields.entry,
			}
			if err := c.Upsert(context.Background(), tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("Upsert() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_Delete(t *testing.T) {
	cfg := ClientConfig{
		SpiffeTrustDomain: "dummy.trusted.domain",
	}
	type fields struct {
		entry entryv1.EntryClient
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "client not initialized",
			wantErr: true,
		},
		{
			name: "unable to list entries due to unknown error",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return nil, fmt.Errorf("something is wrong")
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unable to list entries due to not found error",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return nil, fmt.Errorf("NotFound")
					},
				},
			},
		},
		{
			name: "entry does not exist",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return &entryv1.ListEntriesResponse{}, nil
					},
				},
			},
		},
		{
			name: "entry exists",
			args: args{
				id: "dummy-id",
			},
			fields: fields{
				entry: mockEntryClient{
					ListEntriesFunc: func(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
						require.Equal(t, in, &entryv1.ListEntriesRequest{
							Filter: &entryv1.ListEntriesRequest_Filter{
								BySpiffeId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/identity/dummy-id",
								},
								ByParentId: &types.SPIFFEID{
									TrustDomain: "dummy.trusted.domain",
									Path:        "/cilium-operator",
								},
								BySelectors: &types.SelectorMatch{
									Selectors: []*types.Selector{
										{
											Type:  "cilium",
											Value: "mtls",
										},
									},
									Match: types.SelectorMatch_MATCH_EXACT,
								},
							},
						})
						return &entryv1.ListEntriesResponse{
							Entries: []*types.Entry{{
								Id: "auto-generated-dummy-id",
							}},
						}, nil
					},
					BatchDeleteEntryFunc: func(ctx context.Context, in *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
						require.Equal(t, in, &entryv1.BatchDeleteEntryRequest{
							Ids: []string{"auto-generated-dummy-id"},
						})
						return &entryv1.BatchDeleteEntryResponse{}, nil
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				cfg:   cfg,
				entry: tt.fields.entry,
			}
			if err := c.Delete(context.Background(), tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
