package bpf

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/ebpf"
)

type CollectionLoader interface {
	Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (*ebpf.Collection, func() error, func(), error)
	LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (func() error, func(), error)
}
