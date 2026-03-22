package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// Open opens a FIFO and returns a push-based source.Instance.
// params: path to FIFO, default "/tmp/nodrop.fifo"
func (p *Plugin) Open(params string) (source.Instance, error) {
	fifo := strings.TrimSpace(params)
	if fifo == "" {
		fifo = "/tmp/nodrop.fifo"
	}

	f, err := os.OpenFile(fifo, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return nil, err
	}

	return p.OpenReader(f)
}

// OpenReader reads JSONL events from r and pushes them to Falco as raw events.
// Each line is expected to be a single JSON object.
func (p *Plugin) OpenReader(r io.ReadCloser) (source.Instance, error) {
	evtC := make(chan source.PushEvent)

	go func() {
		defer close(evtC)

		scanner := bufio.NewScanner(r)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			evtC <- source.PushEvent{
				Data: line,
			}
		}

		if err := scanner.Err(); err != nil {
			evtC <- source.PushEvent{Err: err}
		}
	}()

	return source.NewPushInstance(
		evtC,
		source.WithInstanceClose(func() {
			r.Close()
		}),
	)
}
