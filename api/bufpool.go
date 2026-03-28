package api

import "sync"

// BufferPool reduces GC pressure by reusing byte slices.
// Without pooling, every packet allocates a new []byte
// which the garbage collector must later free.
// With pooling, buffers are reused — zero allocation in steady state.
var (
	smallPool = &sync.Pool{New: func() interface{} { return make([]byte, 4*1024) }}
	medPool   = &sync.Pool{New: func() interface{} { return make([]byte, 16*1024) }}
	largePool = &sync.Pool{New: func() interface{} { return make([]byte, 64*1024) }}
)

// GetBuffer returns a pooled buffer of at least the requested size.
func GetBuffer(size int) []byte {
	if size <= 4*1024 {
		return smallPool.Get().([]byte)[:size]
	}
	if size <= 16*1024 {
		return medPool.Get().([]byte)[:size]
	}
	if size <= 64*1024 {
		return largePool.Get().([]byte)[:size]
	}
	return make([]byte, size)
}

// PutBuffer returns a buffer to the pool for reuse.
func PutBuffer(buf []byte) {
	c := cap(buf)
	switch {
	case c >= 64*1024:
		largePool.Put(buf[:c])
	case c >= 16*1024:
		medPool.Put(buf[:c])
	case c >= 4*1024:
		smallPool.Put(buf[:c])
	}
}
