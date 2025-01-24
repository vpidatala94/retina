// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/zap"
)

func GetRingData(e *enricher.Enricher, ctx *context.Context, l *log.ZapLogger) {
	evReader := e.ExportReader()
	for {
		l.Info("Get ring data")
		ev := evReader.NextFollow(*ctx)
		if ev == nil {
			break
		}

		switch ev.Event.(type) {
		case *flow.Flow:
			if flow := ev.GetFlow(); flow != nil {
				if ip := flow.GetIP(); ip != nil {
					if l4 := flow.GetL4(); l4 != nil {
						if tcp := l4.GetTCP(); tcp != nil {
							l.Info("TCP",
								zap.String("FlowType", flow.GetType().String()),
								zap.String("srcIP", ip.Source),
								zap.String("dstIP", ip.Destination),
								zap.Uint32("srcP", tcp.GetSourcePort()),
								zap.Uint32("dstP", tcp.GetDestinationPort()),
							)
						}

						if udp := l4.GetUDP(); udp != nil {
							l.Info("UDP",
								zap.String("FlowType", flow.GetType().String()),
								zap.String("srcIP", ip.Source),
								zap.String("dstIP", ip.Destination),
								zap.Uint32("srcP", udp.GetSourcePort()),
								zap.Uint32("dstP", udp.GetDestinationPort()),
							)
						}
					}
				}
			}
		default:
			l.Warn("Unknown event type", zap.Any("event", ev))
		}
	}

	err := evReader.Close()
	if err != nil {
		l.Error("Error closing the event reader", zap.Error(err))
	}
}

func TestPlugin(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts())
	l := log.Logger().Named("test-ebpf")

	ctx := context.Background()

	cfg := &kcfg.Config{
		MetricsInterval: 1 * time.Second,
		EnablePodLevel:  true,
	}

	c := cache.New(pubsub.New())
	e := enricher.New(ctx, c)
	e.Run()
	defer e.Reader.Close()
	metrics.InitializeMetrics()

	tt := New(cfg)

	err := tt.Stop()
	if err != nil {
		l.Error("Failed to stop windows ebpf plugin", zap.Error(err))
		return
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err = tt.Generate(ctxTimeout)
	if err != nil {
		l.Error("Failed to generate the plugin specific header files", zap.Error(err))
		return
	}

	err = tt.Compile(ctxTimeout)
	if err != nil {
		l.Error("Failed to compile the ebpf to generate bpf object", zap.Error(err))
		return
	}

	err = tt.Init()
	if err != nil {
		l.Error("Failed to initialize plugin specific objects", zap.Error(err))
		return
	}

	// Starting listener routine
	go GetRingData(e, &ctx, l)

	err = tt.Start(ctx)
	if err != nil {
		l.Error("Failed to start windows ebpf plugin", zap.Error(err))
		return
	}
	l.Info("Started windows ebpf plugin")

	defer func() {
		if err := tt.Stop(); err != nil {
			l.Error("Failed to stop windows ebpf plugin", zap.Error(err))
		}
	}()

	for range ctx.Done() {
		// Closing the go routine
		cancel()
	}
}
