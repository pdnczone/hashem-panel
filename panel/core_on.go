//go:build nodecore

package main

import "embed"

// The node core build (go build -tags nodecore): no web page in the binary.
// core.go says what differs from the panel.
const nodeCore = true

var panelFS embed.FS // empty: a core serves no page
