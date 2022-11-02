// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/go-openapi/runtime"
	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"

	clientapi "github.com/cilium/cilium/api/v1/client"
	daemonAPI "github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

var followMapEvents bool

// mapEventListCmd represents the map events command
var mapEventListCmd = &cobra.Command{
	Use:     "events <name>",
	Short:   "Display cached list of events for a BPF map",
	Example: "cilium map events cilium_ipcache",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) == 0 || args[0] == "" {
			Fatalf("map name must be specified")
		}

		var c *clientPkg.Client
		var rt *runtime_client.Runtime
		if r, err := clientPkg.NewRuntime(vp.GetString("host")); err != nil {
			Fatalf("Error while creating client: %s\n", err)
		} else {
			rt = r
		}

		rt.Consumers[runtime.JSONMime] = runtime.ByteStreamConsumer()
		c = &clientPkg.Client{CiliumAPI: *clientapi.New(rt, strfmt.Default)}

		reader, writer := io.Pipe()
		dec := json.NewDecoder(reader)

		ctx, cancel := context.WithCancel(context.Background())
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			w := tabwriter.NewWriter(os.Stdout, 5, 0, 15, ' ', 0)
			if !command.OutputOption() {
				fmt.Fprintf(w, "Timestamp\tAction\tState\tError\tKey\tValue\n")
			}
			for {
				event := &models.MapEvent{}
				err := dec.Decode(&event)
				if err == io.EOF {
					return
				}
				if err != nil {
					Fatalf("error while reading stream: %s", err)
				}
				if command.OutputOption() {
					if err := command.PrintOutput(event); err != nil {
						Fatalf("could not dump data to specified output format: %s", err.Error())
					}
				} else {
					fmt.Fprintf(os.Stdout, "-----------------------------------------\n")
					fmt.Fprintf(os.Stdout, "Key: %s\n", event.Key)
					fmt.Fprintf(os.Stdout, "Value: %s\n", event.Value)
					fmt.Fprintf(os.Stdout, "Time: %s\n", time.Time(event.Timestamp).Format(time.RFC3339))
					fmt.Fprintf(os.Stdout, "Action: %s\n", event.Action)
					fmt.Fprintf(os.Stdout, "Desired Action: %s\n", event.DesiredAction)
					fmt.Fprintf(os.Stdout, "LastError: %s\n", event.LastError)
					w.Flush()
				}
			}
		}()

		params := daemonAPI.NewGetMapNameEventsParamsWithContext(ctx).WithName(args[0]).WithFollow(&followMapEvents)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() {
			<-sig
			cancel()
			fmt.Fprintf(os.Stderr, "\nReceived an interrupt, disconnecting from event stream...\n\n")
			os.Exit(0)
		}()

		_, err := c.Daemon.GetMapNameEvents(params, writer)
		if err != nil {
			Fatalf("could not get map name events: %s", err)
		}

		_ = writer.Close()
		wg.Wait()
	},
}

func init() {
	mapCmd.AddCommand(mapEventListCmd)
	mapEventListCmd.Flags().BoolVarP(&followMapEvents, "follow", "f", false, "If set then events will be streamed")
	command.AddOutputOption(mapEventListCmd)
}
