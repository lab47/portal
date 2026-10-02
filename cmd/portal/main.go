package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	coordinatorConfig := coordinatorFlags.String("config", 0, "", "coordinator config file (default: user config directory/portal/coordinator.json)")
	coordinatorToken := coordinatorFlags.String("token", 0, "", "legacy registration-token override (prefer config)")
	dispatcher.Dispatch("coordinator", mflags.NewCommand(coordinatorFlags, func(_ *mflags.FlagSet, _ []string) error {
		config, err := portal.LoadCoordinatorConfig(*coordinatorConfig)
		if err != nil {
			return err
		}
		registrationToken := config.Token
		if *coordinatorToken != "" {
			registrationToken = *coordinatorToken
		}
		if registrationToken == "" {
			return errors.New("registration token required")
		}
		log.Printf("coordinator listening on %s", *coordinatorListen)
		server := &http.Server{Addr: *coordinatorListen, Handler: portal.NewCoordinator(registrationToken), ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); server.Shutdown(context.Background()) }()
		err = server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}, mflags.WithUsage("Run the inventory coordinator")))

	serverFlags := mflags.NewFlagSet("server")
	name := serverFlags.String("name", 0, "", "inventory name")
	coordinatorURL := serverFlags.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	token := serverFlags.String("token", 0, "", "legacy registration-token override (prefer config)")
	relayURL := serverFlags.String("relay", 0, "", "iroh relay URL (default: number0 production relays)")
	listen := serverFlags.String("listen", 0, "", "optional UDP bind IP:port for direct paths (default: OS-assigned dual-stack port)")
	serverConfig := serverFlags.String("config", 0, "", "server config file (default: user config directory/portal/server.json)")
	caFile := serverFlags.String("ca", 0, "", "trusted SSH user CA public key file or HTTPS URL (overrides embedded key)")
	policyFile := serverFlags.String("policy", 0, "", "JSON authorization policy file (overrides embedded policy)")
	principal := serverFlags.String("principal", 0, "", "required certificate principal (default: admin)")
	var labelFlags []string
	serverFlags.StringArrayNoSplitVar(&labelFlags, "label", 0, nil, "inventory label KEY=VALUE (repeatable)")
	dispatcher.Dispatch("server", mflags.NewCommand(serverFlags, func(_ *mflags.FlagSet, _ []string) error {
		labels := make(map[string]string, len(labelFlags))
		for _, pair := range labelFlags {
			key, value, ok := strings.Cut(pair, "=")
			if !ok || key == "" {
				return fmt.Errorf("invalid label %q: expected KEY=VALUE", pair)
			}
			if _, exists := labels[key]; exists {
				return fmt.Errorf("duplicate label %q", key)
			}
			labels[key] = value
		}
		return (portal.Server{
			Name: *name, CoordinatorURL: *coordinatorURL, Token: *token,
			ConfigFile: *serverConfig, CAFile: *caFile, Principal: *principal, PolicyFile: *policyFile, RelayURL: *relayURL, Listen: *listen, Labels: labels,
		}).Serve(ctx)
	}, mflags.WithUsage("Check in and serve authenticated commands")))

	clientFlags := mflags.NewFlagSet("client")
	clientOptions := clientConnectionFlags(clientFlags)
	user := clientFlags.String("user", 0, "", "local account to run the command as on the server")
	var command []string
	clientFlags.Rest(&command, "command and arguments")
	clientCommand := mflags.NewCommand(clientFlags, func(_ *mflags.FlagSet, _ []string) error {
		client := clientOptions()
		client.User = *user
		response, err := client.Run(ctx, command)
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
	monitorFlags := mflags.NewFlagSet("monitor")
	monitorOptions := clientConnectionFlags(monitorFlags)
	monitorQuery := monitorFlags.String("query", 0, "", "event query (for example: packets where protocol = tcp and dst.port = 80)")
	monitorSource := monitorFlags.String("source", 0, "syscalls", "event source (syscalls, packets, process or disk; use --query for tracepoint)")
	monitorPID := monitorFlags.Int("pid", 0, 0, "filter by process ID (0 matches all)")
	var syscallFlags []string
	monitorFlags.StringArrayNoSplitVar(&syscallFlags, "syscall", 0, nil, "filter by syscall number (repeatable)")
	processName := monitorFlags.String("process-name", 0, "", "filter process events by exact name, prefix* or *suffix")
	processAction := monitorFlags.String("process-action", 0, "", "filter process events by start or exit")
	diskDevice := monitorFlags.String("device", 0, "", "disk kernel device ID (decimal or 0x hex)")
	diskOperation := monitorFlags.String("operation", 0, "", "disk operation: read, write, discard or flush")
	packetProtocol := monitorFlags.String("protocol", 0, "", "packet protocol: tcp or udp")
	packetDirection := monitorFlags.String("direction", 0, "", "packet direction: incoming or outgoing")
	packetSourceIP := monitorFlags.String("src-ip", 0, "", "packet source IP")
	packetDestinationIP := monitorFlags.String("dst-ip", 0, "", "packet destination IP")
	packetSourcePort := monitorFlags.Int("src-port", 0, 0, "packet source port")
	packetDestinationPort := monitorFlags.Int("dst-port", 0, 0, "packet destination port")
	dispatcher.Dispatch("monitor", mflags.NewCommand(monitorFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *monitorQuery != "" {
			for _, name := range []string{"source", "pid", "syscall", "process-name", "process-action", "device", "operation", "protocol", "direction", "src-ip", "dst-ip", "src-port", "dst-port"} {
				if monitorFlags.Lookup(name).HasValue {
					return fmt.Errorf("--query cannot be combined with --%s", name)
				}
			}
			request, err := portal.ParseMonitorQuery(*monitorQuery)
			if err != nil {
				return err
			}
			return monitorOptions().Monitor(ctx, request, func(event portal.Event) error {
				return json.NewEncoder(os.Stdout).Encode(event)
			})
		}
		if *monitorPID < 0 || uint64(*monitorPID) > uint64(^uint32(0)) {
			return errors.New("PID out of range")
		}
		if *packetSourcePort < 0 || *packetSourcePort > 65535 || *packetDestinationPort < 0 || *packetDestinationPort > 65535 {
			return errors.New("packet port out of range")
		}
		request := portal.MonitorRequest{Source: *monitorSource, PID: uint32(*monitorPID)}
		for _, value := range syscallFlags {
			id, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid syscall %q: %w", value, err)
			}
			request.Syscalls = append(request.Syscalls, id)
		}
		if *processName != "" || *processAction != "" {
			request.Process = &portal.ProcessFilter{Name: *processName, Action: *processAction}
		}
		if *diskDevice != "" || *diskOperation != "" {
			request.Disk = &portal.DiskFilter{Operation: *diskOperation}
			if *diskDevice != "" {
				device, err := strconv.ParseUint(*diskDevice, 0, 32)
				if err != nil || device == 0 {
					return fmt.Errorf("invalid device %q", *diskDevice)
				}
				request.Disk.Device = uint32(device)
			}
		}
		if *monitorSource == "packets" || *packetProtocol != "" || *packetDirection != "" || *packetSourceIP != "" || *packetDestinationIP != "" || *packetSourcePort != 0 || *packetDestinationPort != 0 {
			request.Packet = &portal.PacketFilter{
				Protocol: *packetProtocol, Direction: *packetDirection,
				SourceIP: *packetSourceIP, DestinationIP: *packetDestinationIP,
				SourcePort: uint16(*packetSourcePort), DestinationPort: uint16(*packetDestinationPort),
			}
		}
		return monitorOptions().Monitor(ctx, request, func(event portal.Event) error {
			return json.NewEncoder(os.Stdout).Encode(event)
		})
	}, mflags.WithUsage("Stream authenticated server-side eBPF events as JSON lines")))
	registerFlags := mflags.NewFlagSet("monitor-register")
	registerOptions := clientConnectionFlags(registerFlags)
	registerQuery := registerFlags.String("query", 0, "", "event query for the persistent monitor")
	registerTTL := registerFlags.Duration("ttl", 0, portal.DefaultMonitorTTL, "idle lifetime, reset on reads (for example: 30m)")
	dispatcher.Dispatch("monitor-register", mflags.NewCommand(registerFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *registerQuery == "" {
			return errors.New("--query required")
		}
		request, err := portal.ParseMonitorQuery(*registerQuery)
		if err != nil {
			return err
		}
		id, err := registerOptions().CreateMonitor(ctx, request, *registerTTL)
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil
	}, mflags.WithUsage("Register a server-owned monitor and print its ID")))
	readFlags := mflags.NewFlagSet("monitor-read")
	readOptions := clientConnectionFlags(readFlags)
	readID := readFlags.String("id", 0, "", "registered monitor ID")
	readAfter := readFlags.String("after", 0, "0", "last processed sequence (0 starts from beginning)")
	readTimestamp := readFlags.String("after-timestamp", 0, "", "last event TAI64N timestamp (best-effort resume)")
	mcpMode := len(args) > 0 && args[0] == "mcp-server"
	readDefaultDuration := time.Duration(0)
	if mcpMode {
		readDefaultDuration = 5 * time.Second
	}
	readDuration := readFlags.Duration("duration", 0, readDefaultDuration, "maximum read duration (0 follows indefinitely in CLI; MCP requires >0 and <=1m)")
	dispatcher.Dispatch("monitor-read", mflags.NewCommand(readFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *readDuration < 0 || (mcpMode && (*readDuration == 0 || *readDuration > time.Minute)) {
			return errors.New("invalid read duration: MCP requires >0 and <=1m; CLI requires >=0")
		}
		readCtx := ctx
		if *readDuration > 0 {
			var cancel context.CancelFunc
			readCtx, cancel = context.WithTimeout(ctx, *readDuration)
			defer cancel()
		}
		received := false
		onRecord := func(record portal.MonitorRecord) error {
			received = true
			return json.NewEncoder(os.Stdout).Encode(record)
		}
		finish := func(err error) error {
			if received && errors.Is(err, context.DeadlineExceeded) && readCtx.Err() != nil && ctx.Err() == nil {
				return nil
			}
			return err
		}
		if readFlags.Lookup("after-timestamp").HasValue {
			if readFlags.Lookup("after").HasValue {
				return errors.New("--after and --after-timestamp are mutually exclusive")
			}
			return finish(readOptions().ReadMonitorSince(readCtx, *readID, *readTimestamp, onRecord))
		}
		cursor, err := strconv.ParseUint(*readAfter, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid monitor cursor %q: %w", *readAfter, err)
		}
		return finish(readOptions().ReadMonitor(readCtx, *readID, cursor, onRecord))
	}, mflags.WithUsage("Replay records after a sequence, then follow the monitor as JSON lines")))
	deleteFlags := mflags.NewFlagSet("monitor-delete")
	deleteOptions := clientConnectionFlags(deleteFlags)
	deleteID := deleteFlags.String("id", 0, "", "registered monitor ID")
	dispatcher.Dispatch("monitor-delete", mflags.NewCommand(deleteFlags, func(_ *mflags.FlagSet, _ []string) error {
		return deleteOptions().DeleteMonitor(ctx, *deleteID)
	}, mflags.WithUsage("Stop a registered monitor and discard its history")))
	queryFlags := mflags.NewFlagSet("query")
	queryOptions := clientConnectionFlags(queryFlags)
	queryText := queryFlags.String("query", 0, "", "snapshot or aggregation query, optionally followed by | JQ_EXPRESSION")
	queryFormat := queryFlags.String("format", 0, "json", "query output: json (compact aggregates in MCP), legacy, or folded (flame graph stacks)")
	foldedStack := queryFlags.String("folded-stack", 0, "user.stack", "stack grouping to export: user.stack or kernel.stack")
	foldedMetric := queryFlags.Int("folded-metric", 0, 0, "zero-based aggregate metric index for folded weights")
	dispatcher.Dispatch("query", mflags.NewCommand(queryFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *queryText == "" {
			return errors.New("--query required")
		}
		if *queryFormat != "json" && *queryFormat != "legacy" && *queryFormat != "folded" {
			return errors.New("format must be json, legacy or folded")
		}
		request, filter, err := parseClientQuery(*queryText)
		if err != nil {
			return err
		}
		if mcpMode && request.Aggregation != nil && filter == nil && *queryFormat == "json" {
			request.Aggregation.Compact = true
		}
		if *queryFormat == "folded" {
			if filter != nil {
				return errors.New("folded output cannot be combined with a jq pipeline")
			}
			if err := validateFoldedQuery(request, *foldedStack, *foldedMetric); err != nil {
				return err
			}
		}
		snapshot, err := queryOptions().Query(ctx, request)
		if err != nil {
			return err
		}
		if *queryFormat == "folded" {
			if snapshot.Aggregation != nil {
				if stats := snapshot.Aggregation.Collection; stats != nil && *stats != (portal.CollectionStats{}) {
					fmt.Fprintf(os.Stderr, "portal: collection counters: %+v\n", *stats)
				}
			}
			return writeFoldedResult(os.Stdout, snapshot, *foldedStack, *foldedMetric)
		}
		return writeQueryResult(ctx, os.Stdout, snapshot, filter)
	}, mflags.WithUsage("Query server state or aggregates, with optional client-side jq processing")))
	capabilityFlags := mflags.NewFlagSet("capabilities")
	capabilityOptions := clientConnectionFlags(capabilityFlags)
	dispatcher.Dispatch("capabilities", mflags.NewCommand(capabilityFlags, func(_ *mflags.FlagSet, _ []string) error {
		docs, err := capabilityOptions().Capabilities(ctx)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(docs)
	}, mflags.WithUsage("Describe server sources, fields, filters, aggregates and caller authorization as JSON")))
	mcpCommands := mflags.NewDispatcher("portal")
	for _, name := range []string{"client", "capabilities", "query", "monitor-register", "monitor-read", "monitor-delete"} {
		mcpCommands.Dispatch(name, dispatcher.GetCommand(name))
	}
	dispatcher.Dispatch("mcp-server", mflags.NewMCPServerCommand(mcpCommands))

	registerCertCommands(dispatcher)
	registerCACommands(dispatcher, ctx)
	registerConfigCommands(dispatcher)
	registerServerInitCommand(dispatcher, ctx)
	registerCoordinatorInitCommand(dispatcher)
	return dispatcher.Run(args)
}
