// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor"
	monitorapi "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/types"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

type mockProc struct {
	ret uintptr
	err error
}

const (
	pktSizeBytes = 100
)

func makeMockEthernetIPv4TCPPacket() []byte {
	packet := make([]byte, 128)

	// Ethernet header (14 bytes)
	copy(packet[0:6], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})  // Dest MAC
	copy(packet[6:12], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}) // Src MAC
	packet[12] = 0x08                                              // EtherType: 0x0800 = IPv4
	packet[13] = 0x00

	// IPv4 header (20 bytes)
	ipStart := 14
	packet[ipStart+0] = 0x45                            // Version (4) + IHL (5)
	packet[ipStart+1] = 0x00                            // DSCP + ECN
	binary.BigEndian.PutUint16(packet[ipStart+2:], 114) // Total Length (20+20+94=134, but we only use 128 bytes for this mock)
	packet[ipStart+4] = 0x00                            // Identification
	packet[ipStart+5] = 0x01
	packet[ipStart+6] = 0x00 // Flags + Fragment Offset
	packet[ipStart+7] = 0x00
	packet[ipStart+8] = 64 // TTL
	packet[ipStart+9] = 6  // Protocol (TCP)
	// Header checksum left as 0 for mock
	packet[ipStart+12] = 192 // Src IP: 192.168.1.1
	packet[ipStart+13] = 168
	packet[ipStart+14] = 1
	packet[ipStart+15] = 1
	packet[ipStart+16] = 192 // Dst IP: 192.168.1.2
	packet[ipStart+17] = 168
	packet[ipStart+18] = 1
	packet[ipStart+19] = 2

	// TCP header (20 bytes)
	tcpStart := ipStart + 20
	binary.BigEndian.PutUint16(packet[tcpStart+0:], 12345)  // Src port
	binary.BigEndian.PutUint16(packet[tcpStart+2:], 80)     // Dst port
	binary.BigEndian.PutUint32(packet[tcpStart+4:], 0)      // Seq number
	binary.BigEndian.PutUint32(packet[tcpStart+8:], 0)      // Ack number
	packet[tcpStart+12] = 0x50                              // Data offset (5) << 4, no flags
	packet[tcpStart+13] = 0x02                              // SYN flag
	binary.BigEndian.PutUint16(packet[tcpStart+14:], 65535) // Window size
	// TCP checksum and urgent pointer left as 0

	// Payload (fill with pattern)
	payloadStart := tcpStart + 20
	for i := payloadStart; i < 128; i++ {
		packet[i] = byte(i % 256)
	}

	return packet
}

func TestHandleTraceEvent_TraceNotify(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEnricher := enricher.NewMockEnricherInterface(ctrl)
	mockEnricher.EXPECT().Write(gomock.Any()).MinTimes(1)
	mockEnricher.EXPECT().
		Write(gomock.Any()).
		DoAndReturn(func(event *v1.Event) error {
			// Validate the event object here
			// For example, check event type or fields
			fl := event.GetFlow()
			if fl == nil {
				t.Error("expected a flow object, got nil")
			}
			subType := fl.GetEventType().GetSubType()
			if subType != monitorapi.MessageTypeTrace {
				t.Errorf("expected event type %v, got %v", monitorapi.MessageTypeTrace, subType)
			}

			if fl.GetIP().IpVersion != 4 {
				t.Errorf("expected IP version 4, got %v", fl.GetIP().IpVersion)
			}

			if fl.GetIP().Source != "192.168.1.1" {
				t.Errorf("expected source IP to be 192.168.1.1, got %v", fl.GetIP().Source)
			}
			if fl.GetIP().Destination != "192.168.1.2" {
				t.Errorf("expected destination IP to be 192.168.1.2, got %v", fl.GetIP().Destination)
			}
			if _, ok := fl.GetL4().GetProtocol().(*flow.Layer4_TCP); !ok {
				t.Errorf("expected protocol to be TCP(6), got something else")
			}

			if fl.GetL4().GetTCP().SourcePort != 12345 {
				t.Errorf("expected source port to be 12345, got %v", fl.GetL4().GetTCP().SourcePort)
			}
			if fl.GetL4().GetTCP().DestinationPort != 80 {
				t.Errorf("expected destination port to be 80, got %v", fl.GetL4().GetTCP().DestinationPort)
			}
			// Add more assertions as needed
			return nil
		})
	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	p.enricher = mockEnricher

	tn := monitor.TraceNotify{
		TraceNotifyV0: monitor.TraceNotifyV0{
			Type:     monitorapi.MessageTypeTrace,
			ObsPoint: 0,
			Source:   0,
			Hash:     0,
			OrigLen:  0,
			CapLen:   128,
			Version:  1,
			SrcLabel: 0,
			DstLabel: 0,
			DstID:    0,
			Reason:   0,
			Flags:    0,
			Ifindex:  0,
		},
		OrigIP: types.IPv6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, tn); err != nil {
		t.Fatalf("failed to serialize TraceNotify: %v", err)
	}

	// Append mock TCP packet as payload
	packet := makeMockEthernetIPv4TCPPacket()
	buf.Write(packet)

	data := buf.Bytes()

	err := p.handleTraceEvent(unsafe.Pointer(&data), uint32(len(data)))
	if err != nil {
		t.Fatalf("expected no error for handleTraceEvent, got: %v", err)
	}
}

func TestHandleTraceEvent_DropNotify(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEnricher := enricher.NewMockEnricherInterface(ctrl)
	mockEnricher.EXPECT().Write(gomock.Any()).MinTimes(1)
	mockEnricher.EXPECT().
		Write(gomock.Any()).
		DoAndReturn(func(event *v1.Event) error {
			// Validate the event object here
			// For example, check event type or fields
			fl := event.GetFlow()
			if fl == nil {
				t.Error("expected a flow object, got nil")
			}
			subType := fl.GetEventType().GetSubType()
			if subType != monitorapi.MessageTypeTrace {
				t.Errorf("expected event type %v, got %v", monitorapi.MessageTypeTrace, subType)
			}

			if fl.GetIP().IpVersion != 4 {
				t.Errorf("expected IP version 4, got %v", fl.GetIP().IpVersion)
			}

			if fl.GetIP().Source != "192.168.1.1" {
				t.Errorf("expected source IP to be 192.168.1.1, got %v", fl.GetIP().Source)
			}
			if fl.GetIP().Destination != "192.168.1.2" {
				t.Errorf("expected destination IP to be 192.168.1.2, got %v", fl.GetIP().Destination)
			}
			if _, ok := fl.GetL4().GetProtocol().(*flow.Layer4_TCP); !ok {
				t.Errorf("expected protocol to be TCP(6), got something else")
			}

			if fl.GetL4().GetTCP().SourcePort != 12345 {
				t.Errorf("expected source port to be 12345, got %v", fl.GetL4().GetTCP().SourcePort)
			}
			if fl.GetL4().GetTCP().DestinationPort != 80 {
				t.Errorf("expected destination port to be 80, got %v", fl.GetL4().GetTCP().DestinationPort)
			}
			// Add more assertions as needed
			return nil
		})

	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	p.enricher = mockEnricher

	dn := monitor.DropNotify{
		Type:     monitorapi.MessageTypeDrop,
		SubType:  0,
		Source:   0,
		Hash:     0,
		OrigLen:  0,
		CapLen:   128,
		Version:  1,
		SrcLabel: 0,
		DstLabel: 0,
		DstID:    0,
		Line:     0,
		File:     0,
		ExtError: 0,
		Ifindex:  0,
		Flags:    0,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, dn); err != nil {
		t.Fatalf("failed to serialize DropNotify: %v", err)
	}

	// Append mock TCP packet as payload
	packet := makeMockEthernetIPv4TCPPacket()
	buf.Write(packet)

	data := buf.Bytes()

	err := p.handleTraceEvent(unsafe.Pointer(&data), uint32(len(data)))
	if err != nil {
		t.Fatalf("expected no error for handleTraceEvent, got: %v", err)
	}
}

// Negative test case for handleTraceEvent
func TestHandleTraceEvent_UnknownEventType_NoError(t *testing.T) {
	p := &Plugin{l: log.Logger().Named("test-ebpf")}

	// Create a byte array with one byte set to 4 (Unknown event type)
	data := []byte{4} // Neither TraceNotify nor DropNotify
	err := p.handleTraceEvent(unsafe.Pointer(&data), uint32(len(data)))
	if err != nil {
		t.Fatalf("expected no error for unknown event type, got: %v", err)
	}
}

func TestHandleTraceEvent_InvalidTraceNotify(t *testing.T) {
	p := &Plugin{l: log.Logger().Named("test-ebpf")}

	data := []byte{monitorapi.MessageTypeTrace, 0} // Invalid TraceNotify
	err := p.handleTraceEvent(unsafe.Pointer(&data), uint32(len(data)))
	if err == nil {
		t.Fatalf("expected error for invalid TraceNotify, got none")
	} else if err.Error() != "invalid size for TraceNotify 2" {
		t.Fatalf("expected error - invalid size for TraceNotify 2, got: %v", err)
	}
}

func TestHandleTraceEvent_InvalidDropNotify(t *testing.T) {
	p := &Plugin{l: log.Logger().Named("test-ebpf")}

	data := []byte{monitorapi.MessageTypeDrop, 0} // Invalid DropNotify
	err := p.handleTraceEvent(unsafe.Pointer(&data), uint32(len(data)))
	if err == nil {
		t.Fatalf("expected error for invalid DropNotify, got none")
	} else if err.Error() != "invalid size for DropNotify 2" {
		t.Fatalf("expected error - invalid size for DropNotify 2, got: %v", err)
	}
}

func TestHandleTraceEvent_DataNil_SizeNonZero(t *testing.T) {
	p := &Plugin{l: log.Logger().Named("test-ebpf")}

	var mockCiliumEventSize uint32 = 100
	err := p.handleTraceEvent(nil, mockCiliumEventSize)
	if err != nil {
		t.Fatalf("expected error - handleTraceEvent data received is nil")
	} else if err.Error() != "handleTraceEvent data received is nil" {
		t.Fatalf("expected error - handleTraceEvent data received is nil, got %v", err)
	}
}

func TestHandleTraceEvent_InvalidSizeZero(t *testing.T) {
	p := &Plugin{l: log.Logger().Named("test-ebpf")}

	err := p.handleTraceEvent(nil, 0)
	if err != nil {
		t.Fatalf("expected error - invalid size 0")
	} else if err.Error() != "invalid size 0" {
		t.Fatalf("expected error - invalid size 0, got %v", err)
	}
}

func InitalizeMetricsForTesting(ctrl *gomock.Controller) {
	MockGaugeVec := metrics.NewMockGaugeVec(ctrl)
	metrics.DropPacketsGauge = MockGaugeVec
	metrics.DropBytesGauge = MockGaugeVec
	metrics.ForwardBytesGauge = MockGaugeVec
	metrics.ForwardPacketsGauge = MockGaugeVec
}

func TestMetricsMapIterateCallback_DropEgress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)

	// Set expectations BEFORE calling the function under test
	mockDropBytesGauge := metrics.DropBytesGauge.(*metrics.MockGaugeVec)
	mockDropPacketsGauge := metrics.DropPacketsGauge.(*metrics.MockGaugeVec)
	mockDropBytesGauge.EXPECT().
		WithLabelValues("Reason_InvalidPacket", egressLabel).
		Return(mockDropBytesGauge)
	mockDropPacketsGauge.EXPECT().
		WithLabelValues("Reason_InvalidPacket", egressLabel).
		Return(mockDropPacketsGauge)

	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	keyDrop := &MetricsKey{
		Reason:   2,
		Dir:      dirEgress,
		Line:     0,
		File:     0,
		Reserved: [3]uint8{0, 0, 0},
	}
	val := &MetricsValues{{Count: 1, Bytes: pktSizeBytes}}
	p.metricsMapIterateCallback(keyDrop, val)
}

func TestMetricsMapIterateCallback_DropIngress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)

	// Set expectations BEFORE calling the function under test
	mockDropBytesGauge := metrics.DropBytesGauge.(*metrics.MockGaugeVec)
	mockDropPacketsGauge := metrics.DropPacketsGauge.(*metrics.MockGaugeVec)
	mockDropBytesGauge.EXPECT().
		WithLabelValues("Reason_InvalidPacket", ingressLabel).
		Return(mockDropBytesGauge)
	mockDropPacketsGauge.EXPECT().
		WithLabelValues("Reason_InvalidPacket", ingressLabel).
		Return(mockDropPacketsGauge)

	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	keyDrop := &MetricsKey{
		Reason:   2,
		Dir:      dirIngress,
		Line:     0,
		File:     0,
		Reserved: [3]uint8{0, 0, 0},
	}
	val := &MetricsValues{{Count: 1, Bytes: pktSizeBytes}}
	p.metricsMapIterateCallback(keyDrop, val)
}

func TestMetricsMapIterateCallback_ForwardEgress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)

	// Set expectations BEFORE calling the function under test
	mockDropBytesGauge := metrics.ForwardBytesGauge.(*metrics.MockGaugeVec)
	mockDropPacketsGauge := metrics.ForwardPacketsGauge.(*metrics.MockGaugeVec)
	mockDropBytesGauge.EXPECT().
		WithLabelValues(egressLabel).
		Return(mockDropBytesGauge)
	mockDropPacketsGauge.EXPECT().
		WithLabelValues(egressLabel).
		Return(mockDropPacketsGauge)

	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	keyDrop := &MetricsKey{
		Reason:   0,
		Dir:      dirEgress,
		Line:     0,
		File:     0,
		Reserved: [3]uint8{0, 0, 0},
	}
	val := &MetricsValues{{Count: 1, Bytes: pktSizeBytes}}
	p.metricsMapIterateCallback(keyDrop, val)
}

func TestMetricsMapIterateCallback_ForwardIngress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)

	// Set expectations BEFORE calling the function under test
	mockDropBytesGauge := metrics.ForwardBytesGauge.(*metrics.MockGaugeVec)
	mockDropPacketsGauge := metrics.ForwardPacketsGauge.(*metrics.MockGaugeVec)
	mockDropBytesGauge.EXPECT().
		WithLabelValues(ingressLabel).
		Return(mockDropBytesGauge)
	mockDropPacketsGauge.EXPECT().
		WithLabelValues(ingressLabel).
		Return(mockDropPacketsGauge)

	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	keyDrop := &MetricsKey{
		Reason:   0,
		Dir:      dirIngress,
		Line:     0,
		File:     0,
		Reserved: [3]uint8{0, 0, 0},
	}
	val := &MetricsValues{{Count: 1, Bytes: pktSizeBytes}}
	p.metricsMapIterateCallback(keyDrop, val)
}

// Negative test case for IterateWithCallback
func TestMetricsMapIterateCallback_NilKey(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)
	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	fakeValues := &MetricsValues{{}}
	p.metricsMapIterateCallback(nil, fakeValues)
}

func TestMetricsMapIterateCallback_NilValue(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	InitalizeMetricsForTesting(ctrl)
	p := &Plugin{l: log.Logger().Named("test-ebpf")}
	key := &MetricsKey{}
	p.metricsMapIterateCallback(key, nil)
}

func TestIterateWithCallback_Error_NilMetricsValue(t *testing.T) {
	// Mock the function variable to simulate a successful Windows API call
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fakeKey := &MetricsKey{}
	enumCallBack(unsafe.Pointer(fakeKey), nil, 0)
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestIterateWithCallback_Error_ZeroMetricsValueSize(t *testing.T) {
	// Mock the function variable to simulate a successful Windows API call
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fakeKey := &MetricsKey{}
	fakeValues := &MetricsValues{{}}
	enumCallBack(unsafe.Pointer(fakeKey), unsafe.Pointer(&(*fakeValues)[0]), 0)
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestIterateWithCallback_Error_NilMetricsKey(t *testing.T) {
	// Mock the function variable to simulate a successful Windows API call
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fakeValues := &MetricsValues{{}}
	enumCallBack(unsafe.Pointer(nil), unsafe.Pointer(&(*fakeValues)[0]), len(*fakeValues))
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestIterateWithCallback_Error_NilMetricValue(t *testing.T) {
	// Mock the function variable to simulate a successful Windows API call
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fakeValues := &MetricsValues{{}}
	enumCallBack(unsafe.Pointer(nil), unsafe.Pointer(&(*fakeValues)[0]), len(*fakeValues))
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestIterateWithCallback_Success(t *testing.T) {
	// Mock the function variable to simulate a successful Windows API call
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	fakeKey := &MetricsKey{}
	fakeValues := &MetricsValues{{}}
	enumCallBack(unsafe.Pointer(fakeKey), unsafe.Pointer(&(*fakeValues)[0]), len(*fakeValues))
	if !called {
		t.Errorf("expected callback to be called")
	}
}

func TestIterateWithCallback_Error(t *testing.T) {
	// Mock the function variable to simulate an error
	orig := callEnumMetricsMap
	callEnumMetricsMap = func(callback uintptr) (uintptr, uintptr, error) {
		return 1, 0, fmt.Errorf("error")
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != fmt.Errorf("error") {
		t.Fatalf("expected error %v, got %v", fmt.Errorf("error"), err)
	}

	fakeKey := &MetricsKey{}
	fakeValues := &MetricsValues{{}}
	enumCallBack(unsafe.Pointer(fakeKey), unsafe.Pointer(&(*fakeValues)[0]), len(*fakeValues))
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestUnregisterForCallback_Success(t *testing.T) {
	// Mock the function variable
	orig := callUnregisterEventsMapCallback
	callUnregisterEventsMapCallback = func(perfBuffer uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil // Simulate success
	}
	defer func() { callUnregisterEventsMapCallback = orig }()

	em := NewEventsMap()

	err := em.UnregisterForCallback()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestUnregisterForCallback_Error(t *testing.T) {
	// Mock the function variable to simulate an error
	orig := callUnregisterEventsMapCallback
	callUnregisterEventsMapCallback = func(perfBuffer uintptr) (uintptr, uintptr, error) {
		return 1, 0, fmt.Errorf("error")
	}
	defer func() { callUnregisterEventsMapCallback = orig }()

	em := NewEventsMap()

	err := em.UnregisterForCallback()
	if err != fmt.Errorf("error") {
		t.Fatalf("expected error %v, got %v", fmt.Errorf("error"), err)
	}
}

func TestRegisterForCallback_Success(t *testing.T) {
	// Mock the function variable, not the LazyProc
	orig := callRegisterEventsMapCallback
	callRegisterEventsMapCallback = func(callback, perfBuffer uintptr) (uintptr, uintptr, error) {
		return 0, 0, nil // Simulate success
	}
	defer func() { callRegisterEventsMapCallback = orig }()

	logger := log.Logger().Named("test-ebpf")
	em := NewEventsMap()

	called := false
	cb := func(data unsafe.Pointer, size uint32) {
		called = true
	}

	err := em.RegisterForCallback(logger, cb)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Simulate callback
	eventsCallback(nil, 0)
	if !called {
		t.Errorf("expected callback to be called")
	}
}

func TestRegisterForCallback_Error(t *testing.T) {
	// Mock the function variable to simulate an error
	orig := callRegisterEventsMapCallback
	callRegisterEventsMapCallback = func(callback, perfBuffer uintptr) (uintptr, uintptr, error) {
		return 1, 0, fmt.Errorf("error")
	}
	defer func() { callRegisterEventsMapCallback = orig }()

	logger := log.Logger().Named("test-ebpf")
	em := NewEventsMap()

	called := false
	cb := func(data unsafe.Pointer, size uint32) {
		called = true
	}

	err := em.RegisterForCallback(logger, cb)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if called {
		t.Errorf("expected callback not to be called")
	}
}

func TestPlugin(_ *testing.T) {
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
	}
}
