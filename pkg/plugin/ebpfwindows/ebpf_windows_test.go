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

func GetRingData(t *testing.T, e *enricher.Enricher, ctx *context.Context, fltr *FlowFilter) {
	evReader := e.ExportReader()
	for {
		t.Log("Get ring data")
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

							t.Log("TCP",
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

							t.Log("UDP",
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
			t.Log("Unknown event type", zap.Any("event", ev))
		}
	}

	err := evReader.Close()
	if err != nil {
		t.Error("Error closing the event reader", zap.Error(err))
	}
	t.Error("Could not find expected flow object")
}

func StartUDPClient(t *testing.T, serverAddr string) {
	// Resolve the server address
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Error("Error resolving address:", err)
		return
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Error("Error dialing UDP:", err)
		return
	}
	defer conn.Close()

	// Send a message to the server
	message := []byte("Hello, UDP server!")
	_, err = conn.Write(message)
	if err != nil {
		t.Error("Error sending message:", err)
		return
	}
	t.Log("Message sent to server")

	// Set a read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the response from the server
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Error("Error reading response:", err)
		return
	}
	t.Log("Response from server:", string(buffer[:n]))
}

func StartUDPServer(t *testing.T, serverAddr string, ctx context.Context, serverStarted chan<- bool) {
	// Resolve the server address
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Error("Error resolving address:", err)
		serverStarted <- false
		return
	}

	// Create a UDP connection
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Error("Error listening on UDP:", err)
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
			t.Log("UDP server shutting down")
			return
		default:
			// Read from the connection
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				t.Error("Error reading from UDP:", err)
				return
			}

			// Print the received message
			t.Log("Received message from", clientAddr, string(buffer[:n]))

			// Send a response back to the client
			response := []byte("Hello, UDP client!")
			_, err = conn.WriteToUDP(response, clientAddr)
			if err != nil {
				t.Error("Error sending response:", err)
				return
			}
		}
	}
}

func LoadAndAttachBpfProgram(t *testing.T) {
	Ebpfapi := windows.NewLazyDLL("ebpfapi.dll")
	bpf_object__open := Ebpfapi.NewProc("bpf_object__open")
	bpf_object__open.Call("bpf_event_writer.sys")
	if obj == NULL {
		fprintf(stderr, "Failed to open BPF sys file\n")
		return 1
	}

	// Load cilium_events map and tcp_connect bpf program
	if bpf_object__load(obj) < 0 {
		fprintf(stderr, "Failed to load BPF sys\n")
		bpf_object__close(obj)
		return 1
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

	go tt.Start(ctx)
	defer func() {
		if err := tt.Stop(); err != nil {
			l.Error("Failed to stop windows ebpf plugin", zap.Error(err))
		}
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
	t.Log("Preparing to start UDP server")
	go StartUDPServer(t, "127.0.0.1:8080", ctx, serverStarted)
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
	StartUDPClient(t, "127.0.0.1:8080")
	t.Log("UDP client started")
	// Validate results
	GetRingData(t, e, &ctx, flowfltr)
}
