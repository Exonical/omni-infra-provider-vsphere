// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main is the root cmd of the vSphere provider.
package main

import (
    "context"
    _ "embed"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/url"
    "os"
    "os/signal"
    "syscall"

    "github.com/siderolabs/omni/client/pkg/client"
    "github.com/siderolabs/omni/client/pkg/infra"
    "github.com/spf13/cobra"
    "github.com/vmware/govmomi"
    "github.com/vmware/govmomi/find"
    "github.com/vmware/govmomi/property"
    "github.com/vmware/govmomi/vim25/mo"
    "github.com/vmware/govmomi/vim25/types"
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

        // Build dynamic schema with enums from vSphere so UI renders drop-downs
        dynSchema := schema
        if s, derr := buildDynamicSchema(cmd.Context(), vsc); derr == nil {
            dynSchema = s
        } else {
            logger.Warn("failed to build dynamic schema, falling back to static", zap.Error(derr))
        }

        // Infra provider
        ip, err := infra.NewProvider(meta.ProviderID, provisioner, infra.ProviderConfig{
            Name:        cfg.providerName,
            Description: cfg.providerDescription,
            Icon:        base64.RawStdEncoding.EncodeToString(icon),
            Schema:      dynSchema,
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

// buildDynamicSchema queries vSphere inventory and injects enums into the JSON schema
// for fields that should be rendered as drop-downs: datacenter, cluster, datastore, template, port_group.
func buildDynamicSchema(ctx context.Context, vc *govmomi.Client) (string, error) {
    // Unmarshal embedded schema into a generic map
    var m map[string]any
    if err := json.Unmarshal([]byte(schema), &m); err != nil {
        return "", fmt.Errorf("unmarshal schema: %w", err)
    }

    props, _ := m["properties"].(map[string]any)
    if props == nil {
        return "", fmt.Errorf("schema missing properties")
    }

    f := find.NewFinder(vc.Client)

    // Datacenters
    if dcs, err := f.DatacenterList(ctx, "*"); err == nil {
        vals := make([]string, 0, len(dcs))
        for _, dc := range dcs {
            vals = append(vals, dc.Name())
        }
        injectEnum(props, "datacenter", vals)
    }

    // Clusters
    if cls, err := f.ClusterComputeResourceList(ctx, "*"); err == nil {
        vals := make([]string, 0, len(cls))
        for _, c := range cls {
            vals = append(vals, c.Name())
        }
        injectEnum(props, "cluster", vals)
    }

    // Datastores
    if dss, err := f.DatastoreList(ctx, "*"); err == nil {
        vals := make([]string, 0, len(dss))
        for _, ds := range dss {
            vals = append(vals, ds.Name())
        }
        injectEnum(props, "datastore", vals)
    }

    // Networks / Port Groups
    if nets, err := f.NetworkList(ctx, "*"); err == nil {
        vals := make([]string, 0, len(nets))
        for _, n := range nets {
            // Use the managed object reference ID as value; name retrieval is more involved
            vals = append(vals, n.Reference().Value)
        }
        if len(vals) > 0 {
            injectEnum(props, "port_group", vals)
        }
    }

    // Templates: list VMs and filter by Config.Template
    if vms, err := f.VirtualMachineList(ctx, "*"); err == nil {
        pc := property.DefaultCollector(vc.Client)
        refs := make([]types.ManagedObjectReference, 0, len(vms))
        for _, vm := range vms {
            refs = append(refs, vm.Reference())
        }
        var mvm []mo.VirtualMachine
        if err := pc.Retrieve(ctx, refs, []string{"summary", "config"}, &mvm); err == nil {
            vals := make([]string, 0, len(mvm))
            for i, vm := range mvm {
                if vm.Config != nil && vm.Config.Template {
                    vals = append(vals, vms[i].Name())
                }
            }
            if len(vals) > 0 {
                injectEnum(props, "template", vals)
            }
        }
    }

    out, err := json.Marshal(m)
    if err != nil {
        return "", fmt.Errorf("marshal schema: %w", err)
    }
    return string(out), nil
}

func injectEnum(props map[string]any, key string, values []string) {
    p, ok := props[key].(map[string]any)
    if !ok || len(values) == 0 {
        return
    }
    arr := make([]any, 0, len(values))
    for _, v := range values {
        arr = append(arr, v)
    }
    p["enum"] = arr
}
