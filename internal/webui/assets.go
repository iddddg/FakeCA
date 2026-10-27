package webui

import "embed"

// The built Vue application is committed so go build works without Node.
//
//go:embed dist
var dist embed.FS
