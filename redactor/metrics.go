package redactor

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics holds process-lifetime counters for the redaction engine.
// All fields are updated atomically and safe for concurrent use.
// Each counter is padded to its own 64-byte cache line to eliminate false
// sharing between the reader goroutine, 24+ worker goroutines, and the writer.
type Metrics struct {
	ChunksProcessed   atomic.Int64
	_                 [7]int64 // pad to 64 bytes
	BytesIn           atomic.Int64
	_                 [7]int64
	LinesDropped      atomic.Int64
	_                 [7]int64
	WorkerPanics      atomic.Int64
	_                 [7]int64
	WriteErrors       atomic.Int64
	_                 [7]int64
	RedactionsApplied atomic.Int64
	_                 [7]int64
}

// Default is the package-level Metrics instance incremented by ProcessStream.
var Default Metrics

// WritePrometheus writes all counters in Prometheus text exposition format to w.
func (m *Metrics) WritePrometheus(w io.Writer) {
	fmt.Fprintf(w, "# HELP secretscalpel_chunks_processed_total Total chunks dispatched to workers.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_chunks_processed_total counter\n")
	fmt.Fprintf(w, "secretscalpel_chunks_processed_total %d\n\n", m.ChunksProcessed.Load())

	fmt.Fprintf(w, "# HELP secretscalpel_bytes_in_total Total input bytes read.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_bytes_in_total counter\n")
	fmt.Fprintf(w, "secretscalpel_bytes_in_total %d\n\n", m.BytesIn.Load())

	fmt.Fprintf(w, "# HELP secretscalpel_lines_dropped_total Lines dropped for exceeding max length.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_lines_dropped_total counter\n")
	fmt.Fprintf(w, "secretscalpel_lines_dropped_total %d\n\n", m.LinesDropped.Load())

	fmt.Fprintf(w, "# HELP secretscalpel_worker_panics_total Worker goroutine panics recovered.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_worker_panics_total counter\n")
	fmt.Fprintf(w, "secretscalpel_worker_panics_total %d\n\n", m.WorkerPanics.Load())

	fmt.Fprintf(w, "# HELP secretscalpel_write_errors_total Output write errors encountered.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_write_errors_total counter\n")
	fmt.Fprintf(w, "secretscalpel_write_errors_total %d\n\n", m.WriteErrors.Load())

	fmt.Fprintf(w, "# HELP secretscalpel_redactions_applied_total Individual secrets redacted across all input.\n")
	fmt.Fprintf(w, "# TYPE secretscalpel_redactions_applied_total counter\n")
	fmt.Fprintf(w, "secretscalpel_redactions_applied_total %d\n\n", m.RedactionsApplied.Load())
}
