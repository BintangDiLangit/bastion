package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/mcpserver"
)

func main() {
	root := flag.String("root", ".", "project root exposed to Bastion")
	flag.Parse()

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
