// orchestrator.go
package redactor

import (
	"bufio"
	"os"
	"sync"
)

func RunParallel(root *TrieNode, workerCount int) {
	jobs := make(chan Job, workerCount*2)
	results := make(chan Result, workerCount*2)
	var wg sync.WaitGroup

	// Worker Pool
	for range workerCount {
		wg.Go(func() {
			for job := range jobs {
				// MODIFIES IN PLACE: No new string allocation
				RedactBytes(job.Data, root)
				results <- Result{ID: job.ID, Data: job.Data}
			}
		})
	}

	// Ordered Sequencer
	go func() {
		pending := make(map[int][]byte)
		nextID := 0
		newline := []byte("\n")
		for res := range results {
			pending[res.ID] = res.Data
			for {
				data, ok := pending[nextID]
				if !ok {
					break
				}

				// Direct write to the OS buffer
				os.Stdout.Write(data)
				os.Stdout.Write(newline)

				delete(pending, nextID)
				nextID++
			}
		}
	}()

	// Producer
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	lineID := 0
	for scanner.Scan() {
		// We still need this copy because scanner.Bytes() will be
		// overwritten on the next loop iteration.
		line := scanner.Bytes()
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		jobs <- Job{ID: lineID, Data: lineCopy}
		lineID++
	}

	close(jobs)
	wg.Wait()
	close(results)
}
