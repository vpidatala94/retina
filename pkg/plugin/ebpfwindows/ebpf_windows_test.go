// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

type FlowFilter struct {
	dstIP      string
	srcIP      string
	destPort   uint32
	sourcePort uint32
	protocol   string
}

func GetRingData(l *log.ZapLogger, e *enricher.Enricher, ctx *context.Context, fltr *FlowFilter) {
	evReader := e.ExportReader()
	for {
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
							if fltr.protocol == "TCP" && (srcIP != fltr.srcIP || dstIP != fltr.dstIP || dstPrt != fltr.destPort) {
								return
							}
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
							if fltr.protocol == "UDP" && (srcIP != fltr.srcIP || dstIP != fltr.dstIP || dstPrt != fltr.destPort) {
								return
							}
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
}

func StartUDPClient(l *log.ZapLogger, serverAddr string) {
	// Resolve the server address
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		l.Error("Error resolving address:", zap.Error(err))
		return
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		l.Error("Error dialing UDP:", zap.Error(err))
		return
	}
	defer conn.Close()

	// Send a message to the server
	message := []byte("Hello, UDP server!")
	_, err = conn.Write(message)
	if err != nil {
		l.Error("Error sending message:", zap.Error(err))
		return
	}
	l.Info("Message sent to server")
}

func StartUDPServer(l *log.ZapLogger, serverAddr string, ctx context.Context, serverStarted chan<- bool) {
	// Resolve the server address
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		l.Error("Error resolving address:", zap.Error(err))
		serverStarted <- false
		return
	}

	// Create a UDP connection
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		l.Error("Error listening on UDP:", zap.Error(err))
		serverStarted <- false
		return
	}
	defer conn.Close()

	// Signal that the server has started
	serverStarted <- true

	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			l.Info("UDP server shutting down")
			return
		default:
			// Read from the connection
			_, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				l.Error("Error reading from UDP:", zap.Error(err))
				return
			}

			// Print the received message
			l.Info("Received message from", zap.String("clientAddr", clientAddr.String()))
		}
	}
}

func LoadAndAttachBpfProgram(t *testing.T) {
	Ebpfapi := windows.NewLazyDLL("ebpfapi.dll")
	if Ebpfapi == nil {
		t.Error("Error looking up Ebpfapi")
		return
	}
	bpf_object__open := Ebpfapi.NewProc("bpf_object__open")
	bpf_object__load := Ebpfapi.NewProc("bpf_object__load")
	bpf_object__find_program_by_name := Ebpfapi.NewProc("bpf_object__find_program_by_name")
	bpf_object__close := Ebpfapi.NewProc("bpf_object__close")
	bpf_program__attach := Ebpfapi.NewProc("bpf_program__attach")

	obj, _, err := bpf_object__open.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("bpf_event_writer.sys"))))
	if obj == 0 {
		t.Error("Error calling bpf_object__open:", err)
	} else {
		t.Log("bpf_object__open called successfully")
	}
	ret, _, err := bpf_object__load.Call(uintptr(obj))
	if ret == 0 {
		t.Error("Error calling bpf_object__load:", err)
	} else {
		t.Log("bpf_object__load called successfully")
	}
	defer bpf_object__close.Call(obj)
	prg, _, err := bpf_object__find_program_by_name.Call(obj, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("event_writer"))))
	if prg == 0 {
		t.Error("Failed to find event_writer program")
		return
	}

	link, _, err := bpf_program__attach.Call(prg)
	if link == 0 {
		t.Error("BPF program bpf_event_writer.sys failed to attach ", err)
		return
	}
}

func TestUDPTraceEvent(t *testing.T) {
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

	tt.Start(ctx)
	defer func() {
		tt.Stop()
	}()

	flowfltr := &FlowFilter{
		dstIP:      "127.0.0.1",
		srcIP:      "127.0.0.1",
		destPort:   8080,
		sourcePort: 0,
		protocol:   "UDP",
	}

	// Start UDP server
	serverStarted := make(chan bool)
	l.Info("Preparing to start UDP server")
	go StartUDPServer(l, "127.0.0.1:8080", ctx, serverStarted)
	select {
	case success := <-serverStarted:
		if !success {
			t.Error("UDP server failed to start")
			return
		}
	case <-time.After(10 * time.Second): // Adjust the timeout duration as needed
		t.Error("Server start timed out")
		return
	}
	t.Log("UDP server started")
	// Start UDP client
	StartUDPClient(l, "127.0.0.1:8080")
	t.Log("UDP client started")
	// Validate results
	GetRingData(l, e, &ctx, flowfltr)
}
