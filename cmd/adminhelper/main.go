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

	adminhelper "github.com/miren/portal"
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
	dispatcher := mflags.NewDispatcher("adminhelper")

	coordinatorFlags := mflags.NewFlagSet("coordinator")
	coordinatorListen := coordinatorFlags.String("listen", 0, "127.0.0.1:8080", "HTTP listen address")
	coordinatorToken := coordinatorFlags.String("token", 0, os.Getenv("ADMINHELPER_TOKEN"), "server registration token (or ADMINHELPER_TOKEN)")
	dispatcher.Dispatch("coordinator", mflags.NewCommand(coordinatorFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *coordinatorToken == "" {
			return errors.New("registration token required")
		}
		log.Printf("coordinator listening on %s", *coordinatorListen)
		server := &http.Server{Addr: *coordinatorListen, Handler: adminhelper.NewCoordinator(*coordinatorToken), ReadHeaderTimeout: 5 * time.Second}
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
	token := serverFlags.String("token", 0, os.Getenv("ADMINHELPER_TOKEN"), "registration token (or ADMINHELPER_TOKEN)")
	relayURL := serverFlags.String("relay", 0, "", "iroh relay URL (default: number0 production relays)")
	listen := serverFlags.String("listen", 0, "", "optional UDP bind IP:port for direct paths (default: OS-assigned dual-stack port)")
	caFile := serverFlags.String("ca", 0, "", "trusted SSH user CA public key file")
	principal := serverFlags.String("principal", 0, "admin", "required certificate principal")
	dispatcher.Dispatch("server", mflags.NewCommand(serverFlags, func(_ *mflags.FlagSet, _ []string) error {
		return (adminhelper.Server{
			Name: *name, CoordinatorURL: *coordinatorURL, Token: *token,
			CAFile: *caFile, Principal: *principal, RelayURL: *relayURL, Listen: *listen,
		}).Serve(ctx)
	}, mflags.WithUsage("Check in and serve authenticated commands")))

	clientFlags := mflags.NewFlagSet("client")
	clientName := clientFlags.String("name", 0, "", "inventory name")
	clientCoordinatorURL := clientFlags.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	keyFile := clientFlags.String("key", 0, "", "SSH private key file")
	certFile := clientFlags.String("cert", 0, "", "SSH user certificate file")
	var command []string
	clientFlags.Rest(&command, "command and arguments")
	dispatcher.Dispatch("client", mflags.NewCommand(clientFlags, func(_ *mflags.FlagSet, _ []string) error {
		response, err := (adminhelper.Client{
			Name: *clientName, CoordinatorURL: *clientCoordinatorURL, KeyFile: *keyFile, CertFile: *certFile,
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
	}, mflags.WithUsage("Look up a server and run a command")))

	registerCertCommands(dispatcher)
	return dispatcher.Run(args)
}
