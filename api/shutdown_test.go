package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGracefulShutdownOrder(t *testing.T) {
	gs := NewGracefulShutdown(5 * time.Second)

	var mu sync.Mutex
	var order []string

	gs.Register("third", 30, func(ctx context.Context) error {
		mu.Lock()
		order = append(order, "third")
		mu.Unlock()
		return nil
	})
	gs.Register("first", 10, func(ctx context.Context) error {
		mu.Lock()
		order = append(order, "first")
		mu.Unlock()
		return nil
	})
	gs.Register("second", 20, func(ctx context.Context) error {
		mu.Lock()
		order = append(order, "second")
		mu.Unlock()
		return nil
	})

	errs := gs.Execute()
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}

	if len(order) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(order))
	}
	if order[0] != "first" || order[1] != "second" || order[2] != "third" {
		t.Fatalf("wrong order: %v", order)
	}
}

func TestGracefulShutdownErrors(t *testing.T) {
	gs := NewGracefulShutdown(5 * time.Second)

	gs.Register("ok", 1, func(ctx context.Context) error {
		return nil
	})
	gs.Register("fail", 2, func(ctx context.Context) error {
		return errors.New("shutdown failed")
	})

	errs := gs.Execute()
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}

func TestGracefulShutdownOnComplete(t *testing.T) {
	gs := NewGracefulShutdown(5 * time.Second)

	completed := false
	gs.OnComplete(func() {
		completed = true
	})

	gs.Register("task", 1, func(ctx context.Context) error {
		return nil
	})

	gs.Execute()
	if !completed {
		t.Fatal("OnComplete not called")
	}
}

func TestGracefulShutdownDefaultTimeout(t *testing.T) {
	gs := NewGracefulShutdown(0)
	if gs.timeout != 10*time.Second {
		t.Fatalf("expected 10s default, got %v", gs.timeout)
	}
}

func TestGracefulShutdownEmpty(t *testing.T) {
	gs := NewGracefulShutdown(5 * time.Second)
	errs := gs.Execute()
	if len(errs) != 0 {
		t.Fatalf("expected no errors on empty, got %v", errs)
	}
}

func TestGracefulShutdownContextPassed(t *testing.T) {
	gs := NewGracefulShutdown(5 * time.Second)

	var gotCtx context.Context
	gs.Register("check", 1, func(ctx context.Context) error {
		gotCtx = ctx
		return nil
	})

	gs.Execute()
	if gotCtx == nil {
		t.Fatal("context was not passed to handler")
	}
}
