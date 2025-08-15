// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main is the root cmd of the vSphere provider.
package main

import (
    "context"
    _ "embed"
    "encoding/base64"
    "fmt"
    "net/url"
    "os"
    "os/signal"
    "syscall"

    "github.com/siderolabs/omni/client/pkg/client"
    "github.com/siderolabs/omni/client/pkg/infra"
    "github.com/spf13/cobra"
    "github.com/vmware/govmomi"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"

    "github.com/siderolabs/omni-infra-provider-kubevirt/internal/pkg/provider"
    "github.com/siderolabs/omni-infra-provider-kubevirt/internal/pkg/provider/meta"
)

//go:embed data/schema.json
var schema string

//go:embed data/icon.svg
var icon []byte

var (
    debug bool
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
    Use:          "provider",
    Short:        "vSphere Omni infrastructure provider",
    SilenceUsage: true,
    RunE: func(cmd *cobra.Command, _ []string) error {
        // Logger
        loggerCfg := zap.NewProductionConfig()
        if debug {
            loggerCfg = zap.NewDevelopmentConfig()
            loggerCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
            loggerCfg.Level.SetLevel(zap.DebugLevel)
        }
        logger, err := loggerCfg.Build(zap.AddStacktrace(zapcore.ErrorLevel))
        if err != nil {
            return fmt.Errorf("failed to create logger: %w", err)
        }

        // Validate required flags
        if cfg.omniAPIEndpoint == "" {
            return fmt.Errorf("omni-api-endpoint flag is not set")
        }
        if cfg.vsphereURL == "" || cfg.vsphereUsername == "" || cfg.vspherePassword == "" {
            return fmt.Errorf("vsphere-url, vsphere-username and vsphere-password must be set")
        }

        // vSphere client
        vsURL, err := url.Parse(cfg.vsphereURL)
        if err != nil {
            return fmt.Errorf("invalid vSphere URL: %w", err)
        }
        vsURL.User = url.UserPassword(cfg.vsphereUsername, cfg.vspherePassword)

        vsc, err := govmomi.NewClient(cmd.Context(), vsURL, true)
        if err != nil {
            return fmt.Errorf("failed to create vSphere client: %w", err)
        }

        // Provisioner
        provisioner := provider.NewProvisioner(vsc, logger)

        // Infra provider
        ip, err := infra.NewProvider(meta.ProviderID, provisioner, infra.ProviderConfig{
            Name:        cfg.providerName,
            Description: cfg.providerDescription,
            Icon:        base64.RawStdEncoding.EncodeToString(icon),
            Schema:      schema,
        })
        if err != nil {
            return fmt.Errorf("failed to create infra provider: %w", err)
        }

        // Omni client options
        clientOptions := []client.Option{
            client.WithInsecureSkipTLSVerify(cfg.insecureSkipVerify),
        }
        if cfg.serviceAccountKey != "" {
            clientOptions = append(clientOptions, client.WithServiceAccount(cfg.serviceAccountKey))
        }

        // Run
        return ip.Run(cmd.Context(), logger,
            infra.WithOmniEndpoint(cfg.omniAPIEndpoint),
            infra.WithClientOptions(clientOptions...),
            infra.WithEncodeRequestIDsIntoTokens(),
        )
    },
}

var cfg struct {
    omniAPIEndpoint     string
    serviceAccountKey   string
    providerName        string
    providerDescription string
    insecureSkipVerify  bool
    vsphereURL          string
    vsphereUsername     string
    vspherePassword     string
}

func main() {
    if err := app(); err != nil {
        os.Exit(1)
    }
}

func app() error {
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
    defer cancel()

    return rootCmd.ExecuteContext(ctx)
}

func init() {
    rootCmd.Flags().StringVar(&cfg.omniAPIEndpoint, "omni-api-endpoint", os.Getenv("OMNI_ENDPOINT"), "Omni API endpoint")
    rootCmd.Flags().StringVar(&meta.ProviderID, "id", meta.ProviderID, "infra provider id")
    rootCmd.Flags().StringVar(&cfg.serviceAccountKey, "omni-service-account-key", os.Getenv("OMNI_SERVICE_ACCOUNT_KEY"), "Omni service account key")
    rootCmd.Flags().StringVar(&cfg.providerName, "provider-name", "vSphere", "Provider name as it appears in Omni")
    rootCmd.Flags().StringVar(&cfg.providerDescription, "provider-description", "vSphere infrastructure provider", "Provider description as it appears in Omni")
    rootCmd.Flags().BoolVar(&cfg.insecureSkipVerify, "insecure-skip-verify", false, "ignore untrusted certs for Omni API")
    rootCmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")

    // vSphere flags
    rootCmd.Flags().StringVar(&cfg.vsphereURL, "vsphere-url", os.Getenv("VSPHERE_URL"), "vSphere API URL")
    rootCmd.Flags().StringVar(&cfg.vsphereUsername, "vsphere-username", os.Getenv("VSPHERE_USERNAME"), "vSphere username")
    rootCmd.Flags().StringVar(&cfg.vspherePassword, "vsphere-password", os.Getenv("VSPHERE_PASSWORD"), "vSphere password")
}
