package extcommon

import (
	"context"
	"flag"
	"log"
	"strconv"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type SchemaFunc = func() []table.ColumnDefinition
type GenerateFunc = func(context.Context, table.QueryContext) ([]map[string]string, error)
type Tables map[string]struct {
	Schema   SchemaFunc
	Generate GenerateFunc
}

func Main(name string, s SchemaFunc, g GenerateFunc) {
	MainMulti(name, Tables{name: {s, g}})
}

var Verbose *bool
var Timeout, Interval time.Duration

func durationParser(out *time.Duration) func(string) error {
	return func(v string) error {
		if i, e := strconv.Atoi(v); e == nil {
			*out = time.Duration(i) * time.Second
			return nil
		}
		t, err := time.ParseDuration(v)
		if err == nil {
			*out = t
		}
		return err
	}
}

func MainMulti(pluginName string, t Tables) {
	socket := flag.String("socket", "/opt/fleet-orbit/orbit-osquery.em", "path to osquery extensions socket")
	Verbose = flag.Bool("verbose", false, "enable extra debug logging")
	flag.Func("timeout", "timeout for operations and queries", durationParser(&Timeout))
	flag.Func("interval", "interval for operations and queries", durationParser(&Interval))
	flag.Parse()

	if *socket == "" {
		log.Fatal("please specify path to the osquery extensions socket")
	}

	server, err := osquery.NewExtensionManagerServer(pluginName, *socket)
	if err != nil {
		log.Fatalf("failed to connect to osquery socket: %v", err)
	}

	for name, t := range t {
		server.RegisterPlugin(table.NewPlugin(name, t.Schema(), wrapGenerate(name, t.Generate)))
	}
	log.Printf("running server for plugin %q", pluginName)
	if err := server.Run(); err != nil {
		log.Fatalf("failed running server: %v", err)
	}
}

func wrapGenerate(name string, g GenerateFunc) GenerateFunc {
	return func(ctx context.Context, q table.QueryContext) ([]map[string]string, error) {
		out, err := g(ctx, q)
		if err != nil {
			log.Printf("error when querying plugin %q: %v", name, err)
		}
		return out, err
	}
}
