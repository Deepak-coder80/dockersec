package main

import "github.com/Deepak-coder80/dockersec/cmd"

// version is set at build time by goreleaser
var version = "dev"

func main() {
	cmd.Version = version
	cmd.Execute()
}
