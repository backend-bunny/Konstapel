package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
)

// Replay exit statuses: a stored evaluation is never reported as a
// recomputed one, including in the exit status.
const (
	exitReplayRecomputed  = 0
	exitReplayFailed      = 1
	exitReplayUnavailable = 2
)

const replayUsage = `Usage: konstapel replay --package DIR

Replay a continuous assessment package from its local files only: no cluster,
registry, content cache, binding or clock is read. The report prints the
evaluation stored at closure ("stored") and, separately, the re-evaluation of
the package's frozen evaluation inputs ("reevaluation"). Only a package that
records its inputs (Kyverno capture payload 3) is re-evaluated; it must
reproduce its stored evaluation exactly. Earlier packages report the
re-evaluation as Unavailable and are never recomputed with other inputs.

Exit status:
  0  re-evaluated: the frozen inputs reproduce the stored evaluation
  2  re-evaluation unavailable: the package records no evaluation inputs; its
     stored evaluation was retrieved and validated
  1  invalid flags, or a package that cannot be read, validated or
     re-evaluated, or whose re-evaluation differs from its stored evaluation

Flags:
`

// runReplay runs `konstapel replay` and returns its exit status.
func runReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, replayUsage)
		fs.PrintDefaults()
	}
	dir := fs.String("package", "", "package directory (descriptor.json, capture.json, evaluation.json, ...)")
	if err := fs.Parse(args); err != nil {
		return exitReplayFailed
	}
	if *dir == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitReplayFailed
	}
	r, err := c2p.ReplayPackage(*dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitReplayFailed
	}
	b, err := json.MarshalIndent(r.Report(), "", "  ")
	if err == nil {
		_, err = fmt.Fprintf(stdout, "%s\n", b)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitReplayFailed
	}
	if r.Status != c2p.Recomputed {
		return exitReplayUnavailable
	}
	return exitReplayRecomputed
}
