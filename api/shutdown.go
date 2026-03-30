// Package api provides the high-level client and server API for Veil.
//
// This file implements graceful shutdown with drain timeout,
// ensuring active streams complete before server stops.
package api

import (
	"context"
	"sync"
	"time"
)

// GracefulShutdown manages orderly shutdown of all components.
type GracefulShutdown struct {
	mu        sync.Mutex
	tasks     []ShutdownTask
	timeout   time.Duration
	onComplete func()
}

// ShutdownTask represents one component to shut down.
type ShutdownTask struct {
	Name    string
	Handler func(ctx context.Context) error
	Order   int // Lower = earlier
}

// NewGracefulShutdown creates a shutdown manager.
func NewGracefulShutdown(timeout time.Duration) *GracefulShutdown {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &GracefulShutdown{
		timeout: timeout,
	}
}

// Register adds a shutdown task.
func (gs *GracefulShutdown) Register(name string, order int, handler func(ctx context.Context) error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.tasks = append(gs.tasks, ShutdownTask{
		Name:    name,
		Handler: handler,
		Order:   order,
	})
}

// OnComplete sets a callback when all tasks finish.
func (gs *GracefulShutdown) OnComplete(fn func()) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.onComplete = fn
}

// Execute runs all shutdown tasks in order with timeout.
func (gs *GracefulShutdown) Execute() []error {
	gs.mu.Lock()
	tasks := make([]ShutdownTask, len(gs.tasks))
	copy(tasks, gs.tasks)
	gs.mu.Unlock()

	// Sort by order
	for i := 0; i < len(tasks); i++ {
		for j := i + 1; j < len(tasks); j++ {
			if tasks[j].Order < tasks[i].Order {
				tasks[i], tasks[j] = tasks[j], tasks[i]
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), gs.timeout)
	defer cancel()

	var errs []error
	for _, task := range tasks {
		if err := task.Handler(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if gs.onComplete != nil {
		gs.onComplete()
	}

	return errs
}
