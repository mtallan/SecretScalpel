package redactor

import (
	"bufio"
	"os"
	"sync"
)

type Job struct {
	ID   int
	Data []byte
}

type Result struct {
	ID   int
	Data []byte
}

// Changed root *TrieNode to trie *Trie
func RunParallel(trie *Trie, workerCount int) {
	jobs := make(chan Job, workerCount*2)
	results := make(chan Result, workerCount*2)
	var wg sync.WaitGroup

	// Worker Pool
	for i := 0; i < workerCount; i++ {
		wg.Add(1) // Standard Go WaitGroup usage
		go func() {
			defer wg.Done()
			for job := range jobs {
				// Now passing the *Trie manager
				RedactBytes(job.Data, trie)
				results <- Result{ID: job.ID, Data: job.Data}
			}
		}()
	}

	// Ordered Sequencer (Remains mostly the same)
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
				os.Stdout.Write(data)
				os.Stdout.Write(newline)
				delete(pending, nextID)
				nextID++
			}
		}
	}()

	// Producer (Remains mostly the same)
	scanner := bufio.NewScanner(os.Stdin)
	// 1MB buffer for long log lines
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	lineID := 0
	for scanner.Scan() {
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
