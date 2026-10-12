// Package web holds the phone page, built into the assentd binary.
package web

import "embed"

//go:embed index.html app.mjs vcrypto.mjs style.css sw.js manifest.webmanifest icon-32.png icon-180.png icon-192.png icon-512.png
var Files embed.FS
