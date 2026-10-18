package stream

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
)

// repeatReader yields data over and over until limit bytes have been read,
// so a large input can be streamed without holding it in memory or on disk.
type repeatReader struct {
	data  []byte
	off   int
	limit int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.limit <= 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.limit > 0 {
		c := copy(p[n:], r.data[r.off:])
		if int64(c) > r.limit {
			c = int(r.limit)
		}
		n += c
		r.off = (r.off + c) % len(r.data)
		r.limit -= int64(c)
	}
	return n, nil
}

func sampleInput(tb testing.TB) []byte {
	tb.Helper()
	data, err := os.ReadFile("../../input.ndjson")
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

// The input is streamed: memory stays flat however large the input is. This
// pushes 64 MiB through Process and checks that the heap never grows past
// a small bound. The bound is half the input size, so a version that
// buffered the input would fail.
func TestMemoryStaysFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 64 MiB")
	}
	// Twice the heap limit, so a pipeline that kept its input would fail.
	inputSize := int64(64 << 20)
	if raceEnabled {
		inputSize = 8 << 20 // the race detector is about 20x slower
	}
	const heapLimit = 32 << 20

	var peak uint64
	lines := 0
	var ms runtime.MemStats
	in := &repeatReader{data: sampleInput(t), limit: inputSize}
	_, err := Process(in, io.Discard, testEngine(t), Options{
		Workers: runtime.GOMAXPROCS(0),
		AfterLine: func() error {
			lines++
			if lines%20_000 == 0 {
				runtime.ReadMemStats(&ms)
				peak = max(peak, ms.HeapInuse)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("streamed %d MiB in %d lines, peak heap in use %.1f MiB", inputSize>>20, lines, float64(peak)/(1<<20))
	if peak > heapLimit {
		t.Errorf("peak heap %d MiB, want under %d MiB", peak>>20, heapLimit>>20)
	}
}

// BenchmarkProcess measures throughput on the sample input repeated to
// 4 MiB (reported as MB/s by -bench), with one worker and with one per CPU.
func BenchmarkProcess(b *testing.B) {
	data := sampleInput(b)
	eng := testEngine(b)
	const size = 4 << 20
	for _, workers := range []int{1, runtime.GOMAXPROCS(0)} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			b.SetBytes(size)
			b.ReportAllocs()
			for b.Loop() {
				in := &repeatReader{data: data, limit: size}
				if _, err := Process(in, io.Discard, eng, Options{Workers: workers}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
