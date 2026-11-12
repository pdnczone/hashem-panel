//go:build !nodecore

package main

import "embed"

// The panel build: the web page and its files are in the binary. core_on.go
// is the other build (the node core); core.go says what differs.
const nodeCore = false

//go:embed index.html app.js i18n-fa.js fonts.css tokens.css base.css enterprise.css favicon.png favicon.svg apple-touch-icon.png xterm.js xterm-fit.js xterm-search.js xterm.css fonts/vazirmatn.woff2
var panelFS embed.FS
