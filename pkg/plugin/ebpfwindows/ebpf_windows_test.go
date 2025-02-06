// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"context"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

type FiveTuple struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

type Filter struct {
	Event   uint8
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

var (
	Event_WriterDLL = windows.NewLazyDLL("event_writer.dll")
)

func GetRingData(l *log.ZapLogger, e *enricher.Enricher, ctx *context.Context, eventChannel chan int) {
	evReader := e.ExportReader()
	timeout := 180 * time.Second
	timeoutChan := time.After(timeout)
	getData := make(chan *v1.Event)

	go func() {
		ev := evReader.NextFollow(*ctx)
		getData <- ev
	}()

	select {
	case <-timeoutChan:
		l.Info("Timeout reached")
		eventChannel <- 0
		return
	case ev := <-getData:
		if ev == nil {
			l.Info("No more events, breaking loop")
			eventChannel <- 0
			return
		}

		l.Info("Get data")

		switch ev.Event.(type) {
		case *flow.Flow:
			if flow := ev.GetFlow(); flow != nil {
				if ip := flow.GetIP(); ip != nil {
					if l4 := flow.GetL4(); l4 != nil {
						if tcp := l4.GetTCP(); tcp != nil {
							srcIP := ip.Source
							dstIP := ip.Destination
							srcPrt := tcp.GetSourcePort()
							dstPrt := tcp.GetDestinationPort()

							l.Info("TCP",
								zap.String("FlowType", flow.GetType().String()),
								zap.String("srcIP", srcIP),
								zap.String("dstIP", dstIP),
								zap.Uint32("srcP", srcPrt),
								zap.Uint32("dstP", dstPrt),
							)

							if ()
						}

						if udp := l4.GetUDP(); udp != nil {
							srcIP := ip.Source
							dstIP := ip.Destination
							srcPrt := udp.GetSourcePort()
							dstPrt := udp.GetDestinationPort()

							l.Info("UDP",
								zap.String("FlowType", flow.GetType().String()),
								zap.String("srcIP", srcIP),
								zap.String("dstIP", dstIP),
								zap.Uint32("srcP", srcPrt),
								zap.Uint32("dstP", dstPrt),
							)
						}
					}
				}
			}
		default:
			l.Info("Unknown event type", zap.Any("event", ev))
		}
	}

	err := evReader.Close()
	if err != nil {
		l.Error("Error closing the event reader", zap.Error(err))
	}
	l.Error("Could not find expected flow object")
	eventChannel <- 1
}

func GetAllInterfaces(l *log.ZapLogger) []int {
	interfaces, err := net.Interfaces()
	var ifaceList []int
	if err != nil {
		l.Error("Error:", zap.Error(err))
		return nil
	}

	// Iterate over the interfaces and print their indices
	for _, iface := range interfaces {
		ifaceList = append(ifaceList, iface.Index)
	}

	return ifaceList
}

func SetupEventWriter(l *log.ZapLogger) int {
	if Event_WriterDLL == nil {
		l.Error("Error looking up Event_WriterDLL")
		return 1
	}

	pin_maps_load_programs := Event_WriterDLL.NewProc("pin_maps_load_programs")
	ret, _, err := pin_maps_load_programs.Call()
	if ret != 0 {
		l.Error("Failed to load BPF program and map", zap.Error(err))
		return 1
	}

	attach_program_to_interface := Event_WriterDLL.NewProc("attach_program_to_interface")
	ifindexList := GetAllInterfaces(l)
	if len(ifindexList) == 0 {
		l.Error("No interfaces found")
		return 1
	}
	for _, ifidx := range ifindexList {
		attach_program_to_interface.Call(uintptr(ifidx)) // Directly passing integer value as uintptr
	}
	return 0
}

func CloseEventWriter(l *log.ZapLogger) int {
	if Event_WriterDLL == nil {
		l.Error("Error looking up Event_WriterDLL")
		return 1
	}

	unload_programs_detach := Event_WriterDLL.NewProc("unload_programs_detach")
	unload_programs_detach.Call()
	return 0
}

func TestMain(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts())
	l := log.Logger().Named("test-ebpf")
	ctx := context.Background()

	//Load and attach ebpf program
	if ret := SetupEventWriter(l); ret != 0 {
		t.Fail()
		return
	}

	defer CloseEventWriter(l)

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

	go tt.Start(ctx)
	defer func() {
		tt.Stop()
	}()

	if TraceEvent(ctx, e, 4, l) != 0 {
		t.Fail()
	}
}

func TraceEvent(ctx context.Context, e *enricher.Enricher, evt_type uint8, l *log.ZapLogger) int {
	eventChannel := make(chan int)
	set_filter := Event_WriterDLL.NewProc("set_filter")
	//harcoding IP addr for aka.ms - 23.213.38.151
	flt := &Filter{
		Event:   evt_type,
		SrcIP:   399845015,
		DstIP:   0,
		SrcPort: 0,
		DstPort: 0,
	}
	ret, _, err := set_filter.Call(uintptr(unsafe.Pointer(flt)))
	if ret != 0 {
		l.Error("Failed to load BPF program and map", zap.Error(err))
		return 1
	}
	GetRingData(l, e, &ctx, eventChannel)
	return 0
}
