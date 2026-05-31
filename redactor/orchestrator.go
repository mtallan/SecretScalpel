package redactor

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
)

type Job struct {
	Index int
	Data  *bytes.Buffer
}

type Result struct {
	Index int
	Data  *bytes.Buffer
	Err   error // non-nil when the worker failed to process this chunk
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

// processJob redacts all lines in job and returns a pooled result buffer.
// It recovers from panics so a bad chunk never kills the worker goroutine.
func processJob(job Job, trie *Trie) (buf *bytes.Buffer, err error) {
	buf = jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()

	jobDataReturned := false
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Worker panic recovered", "panic", r, "stack", string(debug.Stack()))
			if buf != nil {
				buf.Reset()
				jsonBufPool.Put(buf)
				buf = nil
			}
			if !jobDataReturned && job.Data != nil {
				job.Data.Reset()
				bufferPool.Put(job.Data)
			}
			err = fmt.Errorf("worker panic: %v", r)
		}
	}()

	remaining := job.Data.Bytes()
	var lineCount int64
	for len(remaining) > 0 {
		nl := bytes.IndexByte(remaining, '\n')
		var line []byte
		if nl >= 0 {
			line = remaining[:nl+1]
			remaining = remaining[nl+1:]
		} else {
			line = remaining
			remaining = nil
		}
		lineCount++
		trimmed := bytes.TrimLeft(line, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == '{' {
			redactAllJSONStrings(buf, line, trie)
		} else {
			RedactBytesToWriter(buf, line, trie)
		}
	}
	trie.linesIn.Add(lineCount)

	jobDataReturned = true
	job.Data.Reset()
	bufferPool.Put(job.Data)
	return buf, nil
}

// ProcessStream batches log lines into chunks to eliminate channel contention
// and maximize CPU throughput across all cores. Each line is auto-detected as
// JSON (starts with '{') or raw text and routed to the appropriate redactor.
func ProcessStream(r io.Reader, w io.Writer, trie *Trie, workers int) error {
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
			defer wg.Done()
			for job := range jobs {
				buf, err := processJob(job, trie)
				if err != nil {
					results <- Result{Index: job.Index, Err: err}
				} else {
					results <- Result{Index: job.Index, Data: buf}
				}
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
				// Drain results so workers aren't left blocked on a send.
				for res := range results {
					if res.Data != nil {
						res.Data.Reset()
						jsonBufPool.Put(res.Data)
					}
				}
				errChan <- fmt.Errorf("writer panic: %v", r)
			}
		}()

		expectedIndex := 0
		buffer := make(map[int]*bytes.Buffer)

		// drainAndExit recycles all pending buffers, drains the results channel
		// to unblock any workers still sending, then reports err to errChan.
		// The for-range blocks until results is closed (all workers done).
		drainAndExit := func(err error) {
			for _, v := range buffer {
				v.Reset()
				jsonBufPool.Put(v)
			}
			for res := range results {
				if res.Data != nil {
					res.Data.Reset()
					jsonBufPool.Put(res.Data)
				}
			}
			errChan <- err
		}

		for res := range results {
			if res.Err != nil {
				drainAndExit(res.Err)
				return
			}
			if res.Index == expectedIndex {
				if _, err := w.Write(res.Data.Bytes()); err != nil {
					res.Data.Reset()
					jsonBufPool.Put(res.Data)
					drainAndExit(err)
					return
				}
				res.Data.Reset()
				jsonBufPool.Put(res.Data)
				expectedIndex++

				for {
					if nextData, ok := buffer[expectedIndex]; ok {
						if _, err := w.Write(nextData.Bytes()); err != nil {
							nextData.Reset()
							jsonBufPool.Put(nextData)
							delete(buffer, expectedIndex)
							drainAndExit(err)
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
	var lineBytes int      // bytes accumulated for the current logical line
	var droppingLine bool  // true when current line exceeded maxLineBytes

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
slog.Warn("Input line exceeds limit, dropping remainder", "limit_bytes", maxLineBytes)
				droppingLine = true
			} else {
				currentBatch.Write(line)
				if currentBatch.Len() >= chunkSize {
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
		jobs <- Job{Index: index, Data: currentBatch}
	} else {
		// If the last batch was perfectly sized, the currentBatch is empty.
		// We must return it to the pool to avoid a leak.
		bufferPool.Put(currentBatch)
	}

	close(jobs)

	return <-errChan
}
