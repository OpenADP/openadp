module github.com/openadp/client

go 1.23.0

require github.com/openadp/common v0.1.0

require (
	github.com/flynn/noise v1.1.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/openadp/common => ../common
