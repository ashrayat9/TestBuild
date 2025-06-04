package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v2"
	"inivisirisk.com/pse/config"
	"inivisirisk.com/pse/proxy"
	"inivisirisk.com/pse/server"
)

var (
	policyFile string
	configFile string
	leaksFile string
	globalSession bool
)

func main() {
	authToken := os.Getenv("PSE_DEBUG_FLAG")
	//authToken = "-alsologtostderr"
	flag.CommandLine.Parse(strings.Fields(authToken))
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "serve web",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "policy",
						Usage:       "Policy Configuration",
						Destination: &policyFile,
					},
					&cli.StringFlag{
						Name:        "config",
						Usage:       "configuration",
						Value:       "cfg.yaml",
						Destination: &configFile,
					},
					&cli.StringFlag{
						Name:        "leaks",
						Usage:       "leaks configuration",
						Value:       "leaks.toml",
						Destination: &leaksFile,
					},
					&cli.BoolFlag{
						Name:        "global-session",
						Usage:       "Check if global session is enabled",
						Value:       false,
						Destination: &globalSession,
					},
				},
				Action: func(c *cli.Context) error {
					os.Setenv("LEAKS_FILE_PATH", leaksFile)
					os.Setenv("GLOBAL_SESSION", strconv.FormatBool(globalSession))
					err := config.Set(configFile)
					if err != nil {
						return err
					}
					s := server.StartServer(8081, "policy/policies")
					defer s.Close()
					p := proxy.NewProxy(policyFile)
					p.Start()
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
