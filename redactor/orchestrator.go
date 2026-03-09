package redactor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

type Job struct {
	Index int
	Data  *bytes.Buffer
}

type Result struct {
	Index int
	Data  *bytes.Buffer
}

const (
	// chunkSize is the size of the data chunks fanned out to workers.
	// 256KB is a good balance, large enough to reduce channel overhead but
	// small enough to keep workers busy.
	chunkSize = 256 * 1024

	// maxLineBytes is the maximum number of bytes accepted for a single input
	// line. Lines exceeding this limit are dropped with a warning to prevent
	// unbounded memory growth and slow regex execution on pathological input.
	maxLineBytes = 1024 * 1024 // 1MB
)

// bufferPool holds reusable buffers for the orchestrator to read chunks into.
var bufferPool = sync.Pool{
	New: func() any { return bytes.NewBuffer(make([]byte, 0, chunkSize+4096)) },
}

// ProcessStream batches log lines into chunks to eliminate channel contention
// and maximize CPU throughput across all cores. Cancelling ctx stops the reader
// after the current line; in-flight chunks are drained and written before returning.
func ProcessStream(ctx context.Context, r io.Reader, w io.Writer, triePtr *atomic.Pointer[Trie], isJSON bool, workers int) error {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	// The job channel is intentionally buffered with a small, fixed size.
	// A large buffer (e.g., matching the number of workers) would cause us to
	// hold many large (256KB) chunks in memory simultaneously. A small buffer
	// is sufficient to keep the worker pipeline full without excessive memory use.
	jobs := make(chan Job, 4)
	results := make(chan Result, workers)

	var wg sync.WaitGroup

	// 1. Spin up the Worker Pool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer func() {
				// Ensure wg.Done() is always called, even if a panic occurs.
				// This prevents the entire application from hanging.
				if r := recover(); r != nil {
					Default.WorkerPanics.Add(1)
					slog.Error("Worker panic recovered", "panic", r, "stack", string(debug.Stack()))
				}
				wg.Done()
			}()
			for job := range jobs {
				jobBytes := job.Data.Bytes()
				var resultBuf *bytes.Buffer

				trie := triePtr.Load()
				if isJSON {
					// The ToBuffer function returns the buffer, caller must return it to the pool.
					resultBuf = RedactAllJSONStringsToBuffer(jobBytes, trie)
				} else {
					// For the raw path, write directly into a pooled buffer to avoid the
					// intermediate allocation that RedactBytes() would perform.
					resultBuf = jsonBufPool.Get().(*bytes.Buffer)
					resultBuf.Reset()
					RedactBytesToWriter(resultBuf, jobBytes, trie)
				}
				// After use, reset and return the buffer to the pool.
				job.Data.Reset()
				bufferPool.Put(job.Data)

				results <- Result{Index: job.Index, Data: resultBuf}
			}
		}()
	}

	// 2. Closer Goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// 3. Order-Preserving Writer Goroutine
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Writer panic recovered", "panic", r, "stack", string(debug.Stack()))
				errChan <- fmt.Errorf("writer panic: %v", r)
			}
		}()

		expectedIndex := 0
		buffer := make(map[int]*bytes.Buffer)

		for res := range results {
			if res.Index == expectedIndex {
				if _, err := w.Write(res.Data.Bytes()); err != nil {
					Default.WriteErrors.Add(1)
					errChan <- err
					return
				}
				res.Data.Reset()
				jsonBufPool.Put(res.Data)
				expectedIndex++

				for {
					if nextData, ok := buffer[expectedIndex]; ok {
						if _, err := w.Write(nextData.Bytes()); err != nil {
							errChan <- err
							return
						}
						nextData.Reset()
						jsonBufPool.Put(nextData)
						delete(buffer, expectedIndex)
						expectedIndex++
					} else {
						break
					}
				}
			} else {
				buffer[res.Index] = res.Data
			}
		}
		errChan <- nil
	}()

	// 4. The Block Reader
	// The buffer size for the reader should be larger than the chunkSize to be
	// efficient, but the previous 4MB was excessive and dominated memory usage
	// in benchmarks. 1MB is a more reasonable default.
	reader := bufio.NewReaderSize(r, 1024*1024)
	index := 0

	currentBatch := bufferPool.Get().(*bytes.Buffer)
	var lineBytes int     // bytes accumulated for the current logical line
	var droppingLine bool // true when current line exceeded maxLineBytes
	var localBytesIn int64 // batched counter flushed at each chunk dispatch

	for {
		line, err := reader.ReadSlice('\n')
		// ErrBufferFull means the line continues; any other err (nil or EOF)
		// means this fragment ends the logical line.
		endsLine := err != bufio.ErrBufferFull

		if len(line) > 0 {
			lineBytes += len(line)
			if droppingLine {
				// discard fragment; wait for end of this line
			} else if lineBytes > maxLineBytes {
				Default.LinesDropped.Add(1)
				slog.Warn("Input line exceeds limit, dropping remainder", "limit_bytes", maxLineBytes)
				droppingLine = true
			} else {
				localBytesIn += int64(len(line))
				currentBatch.Write(line)
				if currentBatch.Len() >= chunkSize {
					Default.BytesIn.Add(localBytesIn)
					localBytesIn = 0
					Default.ChunksProcessed.Add(1)
					if ctx.Err() != nil {
						break
					}
					jobs <- Job{Index: index, Data: currentBatch}
					index++
					currentBatch = bufferPool.Get().(*bytes.Buffer)
				}
			}
		}

		if endsLine {
			lineBytes = 0
			droppingLine = false
		}

		if err != nil {
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != io.EOF {
				return err
			}
			break
		}
	}

	// Dispatch the final partial chunk
	if currentBatch.Len() > 0 {
		Default.BytesIn.Add(localBytesIn)
		Default.ChunksProcessed.Add(1)
		jobs <- Job{Index: index, Data: currentBatch}
	} else {
		// If the last batch was perfectly sized, the currentBatch is empty.
		// We must return it to the pool to avoid a leak.
		bufferPool.Put(currentBatch)
	}

	close(jobs)

	return <-errChan
}
