package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lab47/portal"
	"miren.dev/mflags"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dispatcher := mflags.NewDispatcher("portal")

	coordinatorFlags := mflags.NewFlagSet("coordinator")
	coordinatorListen := coordinatorFlags.String("listen", 0, "127.0.0.1:8080", "HTTP listen address")
	coordinatorToken := coordinatorFlags.String("token", 0, os.Getenv("PORTAL_TOKEN"), "server registration token (or PORTAL_TOKEN)")
	dispatcher.Dispatch("coordinator", mflags.NewCommand(coordinatorFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *coordinatorToken == "" {
			return errors.New("registration token required")
		}
		log.Printf("coordinator listening on %s", *coordinatorListen)
		server := &http.Server{Addr: *coordinatorListen, Handler: portal.NewCoordinator(*coordinatorToken), ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); server.Shutdown(context.Background()) }()
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}, mflags.WithUsage("Run the inventory coordinator")))

	serverFlags := mflags.NewFlagSet("server")
	name := serverFlags.String("name", 0, "", "inventory name")
	coordinatorURL := serverFlags.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	token := serverFlags.String("token", 0, os.Getenv("PORTAL_TOKEN"), "registration token (or PORTAL_TOKEN)")
	relayURL := serverFlags.String("relay", 0, "", "iroh relay URL (default: number0 production relays)")
	listen := serverFlags.String("listen", 0, "", "optional UDP bind IP:port for direct paths (default: OS-assigned dual-stack port)")
	caFile := serverFlags.String("ca", 0, "", "trusted SSH user CA public key file")
	policyFile := serverFlags.String("policy", 0, "", "required JSON authorization policy file")
	principal := serverFlags.String("principal", 0, "admin", "required certificate principal")
	dispatcher.Dispatch("server", mflags.NewCommand(serverFlags, func(_ *mflags.FlagSet, _ []string) error {
		return (portal.Server{
			Name: *name, CoordinatorURL: *coordinatorURL, Token: *token,
			CAFile: *caFile, Principal: *principal, PolicyFile: *policyFile, RelayURL: *relayURL, Listen: *listen,
		}).Serve(ctx)
	}, mflags.WithUsage("Check in and serve authenticated commands")))

	clientFlags := mflags.NewFlagSet("client")
	clientName := clientFlags.String("name", 0, "", "inventory name")
	clientCoordinatorURL := clientFlags.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	keyFile := clientFlags.String("key", 0, "", "SSH private key file")
	certFile := clientFlags.String("cert", 0, "", "SSH user certificate file")
	user := clientFlags.String("user", 0, "", "local account to run the command as on the server")
	var command []string
	clientFlags.Rest(&command, "command and arguments")
	clientCommand := mflags.NewCommand(clientFlags, func(_ *mflags.FlagSet, _ []string) error {
		response, err := (portal.Client{
			Name: *clientName, CoordinatorURL: *clientCoordinatorURL, KeyFile: *keyFile, CertFile: *certFile, User: *user,
		}).Run(ctx, command)
		if err != nil {
			return err
		}
		fmt.Print(response.Output)
		if response.Error != "" {
			return errors.New(response.Error)
		}
		if response.ExitCode != 0 {
			return fmt.Errorf("remote exit code %d", response.ExitCode)
		}
		return nil
	}, mflags.WithUsage("Look up a server and run a command (MCP arguments: prefix the command array with -- to preserve remote flags)"))
	dispatcher.Dispatch("client", clientCommand)
	mcpCommands := mflags.NewDispatcher("portal")
	mcpCommands.Dispatch("client", clientCommand)
	dispatcher.Dispatch("mcp-server", mflags.NewMCPServerCommand(mcpCommands))

	registerCertCommands(dispatcher)
	return dispatcher.Run(args)
}
