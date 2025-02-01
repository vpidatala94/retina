// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"context"
	"net"
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
	"golang.org/x/sys/windows"
)

type FlowFilter struct {
	dstIP      string
	srcIP      string
	destPort   uint32
	sourcePort uint32
	protocol   string
}

var (
	Event_WriterDLL = windows.NewLazyDLL("event_writer.dll")
)

func GetRingData(l *log.ZapLogger, e *enricher.Enricher, ctx *context.Context, fltr *FlowFilter) int {
	evReader := e.ExportReader()
	startTime := time.Now()
	timeout := 10 * time.Second
	for {
		if time.Since(startTime) > timeout {
			l.Info("Timeout reached")
			return 0
		}
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
								return 0
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
								return 0
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
	return 1
}

func StartTCPServer(l *log.ZapLogger, serverAddr string, ctx context.Context, serverStarted chan<- bool) {
	// Resolve the server address
	addr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		l.Error("Error resolving address:", zap.Error(err))
		serverStarted <- false
		return
	}

	// Create a TCP listener
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		l.Error("Error listening on TCP:", zap.Error(err))
		serverStarted <- false
		return
	}
	defer ln.Close()

	// Signal that the server has started
	serverStarted <- true

	for {
		select {
		case <-ctx.Done():
			l.Info("TCP server shutting down")
			return
		default:
			// Accept incoming TCP connections
			conn, err := ln.AcceptTCP()
			if err != nil {
				l.Error("Error accepting TCP connection:", zap.Error(err))
				return
			}

			// Handle the TCP connection
			l.Info("Received TCP connection from", zap.String("clientAddr", conn.RemoteAddr().String()))

			// Read the data from the connection
			buffer := make([]byte, 1024)
			_, err = conn.Read(buffer)
			if err != nil {
				l.Error("Error reading from TCP connection:", zap.Error(err))
				conn.Close()
				return
			}

			// Print the received message
			l.Info("Received message from client: ", zap.String("message", string(buffer)))
			conn.Close()
		}
	}
}

func StartTCPClient(l *log.ZapLogger, serverAddr string) {
	// Resolve the server address
	addr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		l.Error("Error resolving address:", zap.Error(err))
		return
	}

	// Create a TCP connection
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		l.Error("Error dialing TCP:", zap.Error(err))
		return
	}
	defer conn.Close()

	// Send a message to the server
	message := []byte("Hello, TCP server!")
	_, err = conn.Write(message)
	if err != nil {
		l.Error("Error sending message:", zap.Error(err))
		return
	}
	l.Info("Message sent to server")
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

func StartUDPExchange(ctx context.Context, l *log.ZapLogger) int {
	// Start UDP server
	serverStarted := make(chan bool)
	l.Info("Preparing to start UDP server")
	go StartUDPServer(l, "127.0.0.1:8080", ctx, serverStarted)
	select {
	case success := <-serverStarted:
		if !success {
			l.Error("UDP server failed to start")
			return 1
		}
	case <-time.After(10 * time.Second): // Adjust the timeout duration as needed
		l.Error("Server start timed out")
		return 1
	}
	l.Info("UDP server started")
	// Start UDP client
	StartUDPClient(l, "127.0.0.1:8000")
	l.Info("UDP client started")
	return 0
}

func StartTCPExchange(ctx context.Context, l *log.ZapLogger) int {
	// Start TCP server
	serverStarted := make(chan bool)
	l.Info("Preparing to start TCP server")
	go StartTCPServer(l, "127.0.0.1:8080", ctx, serverStarted)
	select {
	case success := <-serverStarted:
		if !success {
			l.Error("TCP server failed to start")
			return 1
		}
	case <-time.After(10 * time.Second): // Adjust the timeout duration as needed
		l.Error("Server start timed out")
		return 1
	}
	l.Info("TCP server started")

	// Start TCP client
	StartTCPClient(l, "127.0.0.1:8080")
	l.Info("TCP client started")
	return 0
}

func LoadAndAttachBpfProgram(l *log.ZapLogger) int {
	if Event_WriterDLL == nil {
		l.Error("Error looking up Event_WriterDLL")
		return 1
	}

	pin_maps_load_attach_programs := Event_WriterDLL.NewProc("pin_maps_load_attach_programs")
	pin_maps_load_attach_programs.Call()
	return 0
}

func DetachBpfProgram(l *log.ZapLogger) int {
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
	if ret := LoadAndAttachBpfProgram(l); ret != 0 {
		t.Fail()
		return
	}
	defer DetachBpfProgram(l)

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

	//TRACE ; TCP
	if CreateEvent(ctx, e, 4, "TCP", l) != 0 {
		t.Fail()
	}

	//TRACE ; UDP
	if CreateEvent(ctx, e, 4, "UDP", l) != 0 {
		t.Fail()
	}

	//DROP ; TCP
	if CreateEvent(ctx, e, 1, "TCP", l) != 0 {
		t.Fail()
	}

	//DROP ; UDP
	if CreateEvent(ctx, e, 1, "UDP", l) != 0 {
		t.Fail()
	}
}

func CreateEvent(ctx context.Context, e *enricher.Enricher, evt_type uint8, proto string, l *log.ZapLogger) int {
	flowfltr := &FlowFilter{
		dstIP:      "127.0.0.1",
		srcIP:      "127.0.0.1",
		destPort:   8080,
		sourcePort: 8000,
		protocol:   proto,
	}

	set_event_type := Event_WriterDLL.NewProc("set_event_type")
	l.Info("Setting event type", zap.Uint8("evt_type", evt_type))
	set_event_type.Call(uintptr(evt_type))
	// Validate results
	if proto == "TCP" {
		if ret := StartTCPExchange(ctx, l); ret != 0 {
			return ret
		}
	} else {
		if ret := StartUDPExchange(ctx, l); ret != 0 {
			return ret
		}
	}

	return GetRingData(l, e, &ctx, flowfltr)
}
