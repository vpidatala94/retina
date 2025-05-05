// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package ebpfwindows

import (
	"context"
	"testing"
	"time"
	"unsafe"

	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

type mockProc struct {
	ret uintptr
	err error
}

// Value must be in sync with struct metrics_key in <bpf/lib/common.h>
type MetricsKey_noncompliant struct {
	Reason uint8 `align:"reason"`
	Dir    uint8 `align:"dir"`
	// Line contains the line number of the metrics statement.
	Line uint16 `align:"line"`
	// File is the number of the source file containing the metrics statement.
	File     uint8    `align:"file"`
	Reserved [3]uint8 `align:"reserved"`
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type MetricsValue_noncompliant struct {
	Count uint64 `align:"count"`
	Bytes uint64 `align:"bytes"`
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
		return 1, 0, windows.ERROR_INVALID_PARAMETER
	}
	defer func() { callEnumMetricsMap = orig }()

	m := NewMetricsMap()
	logger := log.Logger().Named("test-ebpf")

	called := false
	err := m.IterateWithCallback(logger, func(key *MetricsKey, values *MetricsValues) {
		called = true
	})
	if err != windows.ERROR_INVALID_PARAMETER {
		t.Fatalf("expected error %v, got %v", windows.ERROR_INVALID_PARAMETER, err)
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
		return 1, 0, windows.ERROR_INVALID_PARAMETER
	}
	defer func() { callUnregisterEventsMapCallback = orig }()

	em := NewEventsMap()

	err := em.UnregisterForCallback()
	if err != windows.ERROR_INVALID_PARAMETER {
		t.Fatalf("expected error %v, got %v", windows.ERROR_INVALID_PARAMETER, err)
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
		return 1, 0, windows.ERROR_INVALID_PARAMETER
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
