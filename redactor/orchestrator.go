package redactor

import (
	"bufio"
	"bytes"
	"io"
	"runtime"
	"sync"
)

type Job struct {
	Index int
	Data  []byte
}

type Result struct {
	Index int
	Data  []byte
}

// ProcessStream batches log lines into chunks to eliminate channel contention
// and maximize CPU throughput across all cores.
func ProcessStream(r io.Reader, w io.Writer, trie *Trie, isJSON bool, workers int) error {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	jobs := make(chan Job, workers)
	results := make(chan Result, workers)

	var wg sync.WaitGroup

	// 1. Spin up the Worker Pool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				var redacted []byte
				if isJSON {
					redacted = RedactAllJSONStrings(job.Data, trie)
				} else {
					redacted = RedactBytes(job.Data, trie)
				}
				results <- Result{Index: job.Index, Data: redacted}
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
		expectedIndex := 0
		buffer := make(map[int][]byte)

		for res := range results {
			if res.Index == expectedIndex {
				w.Write(res.Data)
				expectedIndex++

				for {
					if nextData, ok := buffer[expectedIndex]; ok {
						w.Write(nextData)
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

	// 4. The Block Reader (The Fix)
	// We read lines, but pack them into a 256KB buffer before sending to a worker.
	reader := bufio.NewReaderSize(r, 1024*1024)
	index := 0

	// Pre-allocate a large chunk to avoid slice growth allocations
	chunkSize := 256 * 1024
	var currentBatch bytes.Buffer
	currentBatch.Grow(chunkSize + 4096)

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			currentBatch.Write(line)

			// If we've hit our chunk limit, dispatch it to a core
			if currentBatch.Len() >= chunkSize {
				// We must copy the batch because we are resetting the buffer
				batchCopy := make([]byte, currentBatch.Len())
				copy(batchCopy, currentBatch.Bytes())

				jobs <- Job{Index: index, Data: batchCopy}
				index++
				currentBatch.Reset()
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}

	// Dispatch the final partial chunk
	if currentBatch.Len() > 0 {
		batchCopy := make([]byte, currentBatch.Len())
		copy(batchCopy, currentBatch.Bytes())
		jobs <- Job{Index: index, Data: batchCopy}
	}

	close(jobs)

	<-errChan
	return nil
}
