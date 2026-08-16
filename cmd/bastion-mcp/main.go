package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/mcpserver"
)

// Build metadata, injected at link time with -X main.<name>=<value>.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	root := flag.String("root", ".", "project root exposed to Bastion")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	// MCP servers are launched by an opaque client config, so this flag is the
	// only way a bug reporter can tell which build they actually have on disk.
	if *showVersion {
		fmt.Printf("bastion-mcp %s (commit %s, built %s by %s)\n", version, commit, date, builtBy)
		return
	}

	logger := logrus.New()
	logger.SetOutput(os.Stderr)
	logger.SetLevel(logrus.WarnLevel)

	service, err := mcpserver.New(*root, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := service.Server().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
