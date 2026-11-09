Miu protocol implementation from https://github.com/xiangwan6667/Miu
commit 08dbc75484abd9249c4a9534a43458aee144dbe6.

The Go files in this directory are from the upstream `miu` package. Local fixes
in `client.go`, `stream.go` and `packet.go` make connection setup honor
cancellation and UDP write deadlines, and return a nil connection on dial
failure. Tests use the local `testdata` directory and Go 1.20-compatible syntax.
See LICENSE.
