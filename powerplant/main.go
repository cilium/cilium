package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/rand"
)

type reactor struct {
	healthReporter cell.StatusReporter
	lc             hive.Lifecycle
	cooling        *coolingSystem

	fuelRods int
}

func newReactor(hr cell.StatusReporter, lc hive.Lifecycle, c *coolingSystem) *reactor {
	r := &reactor{
		healthReporter: hr,
		lc:             lc,
		cooling:        c,
	}
	lc.Append(r)
	return r
}

func (r *reactor) Info() string {
	return "CANDU Deuterium Reactor - Mk. 1" +
		"\n\tFuel Rods: " + fmt.Sprintf("%d", r.fuelRods)
}

type coolingSystem struct{}

func (c *coolingSystem) Run() error {
	temp := rand.IntnRange(0, 3000)
	if temp > 2000 {
		return fmt.Errorf("cooling system failure: reactor temperature is %d", temp)
	}
	return nil
}

func newCoolingSystem() *coolingSystem {
	return &coolingSystem{}
}

type healthServer struct {
	healthReporter cell.StatusReporter
}

func moduleHealthServer(lc hive.Lifecycle) *healthServer {
	hs := &healthServer{}
	lc.Append(hs)
	return hs
}

func (h *healthServer) Start(hive.HookContext) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/module-health", func(w http.ResponseWriter, r *http.Request) {
		logrus.Info("Health check requested")
		//fmt.Fprintf(w, powerPlant.String())
	})
	fmt.Println("Starting health server")
	go func() {
		if err := http.ListenAndServe(":8080", mux); err != nil {
			//h.healthReporter.Degraded(hive.NewIssue("health server failure")(err))
			h.healthReporter.Degraded(fmt.Sprintf("Failed to start health server: %v", err))
		}
	}()
	return nil
}

func (h *healthServer) Stop(hive.HookContext) error {
	fmt.Println("Stopping health server")
	return nil
}

func (r *reactor) Start(hive.HookContext) error {
	fmt.Println("Plant is starting up")
	fmt.Println("Reactor:", r.Info())
	for {
		if err := r.cooling.Run(); err != nil {
			r.healthReporter.Degraded("Cooling system failure: " + err.Error())
		} else {
			r.healthReporter.OK("Temp is within range")
		}

		time.Sleep(time.Second * 5)
	}
}

func (s *reactor) Stop(ctx hive.HookContext) error {
	fmt.Println("Plant is shutting down")
	return nil
}

var controlPlane = cell.Module("control-plane", "Control Plane for Nuclear Power Plant",
	cell.Provide(newCoolingSystem),
	cell.Provide(newReactor),
	cell.Invoke(func(r *reactor) {}),
)

var infrastructure = cell.Module("infrastructure", "Infrastructure for Nuclear Power Plant",
	cell.Module(
		"health-server",
		"Health HTTP Server",
		cell.Provide(moduleHealthServer),
		cell.Invoke(func(hs *healthServer) {}),
	),
)

var powerPlant = hive.New(
	infrastructure,
	controlPlane,
)

func main() {
	if err := powerPlant.Run(); err != nil {
		logrus.Fatal(err)
	}
}
