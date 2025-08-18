// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package provider implements vSphere infra provider core.
package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/siderolabs/omni/client/pkg/infra/provision"
	"github.com/siderolabs/omni/client/pkg/omni/resources/infra"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vapi/library"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/vcenter"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"github.com/vmware/govmomi/view"
	"go.uber.org/zap"

	"github.com/siderolabs/omni-infra-provider-vsphere/internal/pkg/provider/resources"
)

// Provisioner implements the vSphere infra provider.
// It is responsible for the entire lifecycle of a virtual machine.
// It uses the govmomi library to interact with the vSphere API.
// The main steps are:
// 1. Generate a schematic ID for the machine.
// 2. Find all the necessary vSphere objects (Datacenter, Cluster, Datastore, etc.).
// 3. Clone the template VM.
// 4. Reconfigure the VM's hardware (CPU, memory, disk).
// 5. Add the cloud-init user data via guestinfo.
// 6. Power on the VM.
// 7. Wait for the VM to get an IP address.
// 8. Store the VM's UUID in the state.
// 9. Deprovision the VM by powering it off and destroying it.
type Provisioner struct {
	vsphereClient *govmomi.Client
	logger        *zap.Logger
}

// buildJoinConfigWithOptionalAdditions appends optional YAML documents to the provided JoinConfig:
// - TrustedRootsConfig if OMNI_CA_BUNDLE_PATH or OMNI_CA_BUNDLE is set
// - MachineConfig to set the hostname to vmName if vmName is non-empty
//
// apiVersion: v1alpha1
// kind: TrustedRootsConfig
// name: custom-ca
// certificates: |-
//     <PEM>
//
// The result is returned as a single multi-document YAML string.
func buildJoinConfigWithOptionalAdditions(baseJoinConfig, _ string) string {
    // Prefer file path, fallback to direct content.
    caPath := os.Getenv("OMNI_CA_BUNDLE_PATH")
    caPEM := os.Getenv("OMNI_CA_BUNDLE")

    if caPath != "" {
        if b, err := os.ReadFile(caPath); err == nil {
            caPEM = string(b)
        }
    }

    caPEM = strings.TrimSpace(caPEM)
    // We'll build output incrementally; start with base config.
    out := strings.TrimRight(baseJoinConfig, "\n") + "\n"

    if caPEM == "" {
        return out
    }

    // If the provided value doesn't look like PEM, try to base64-decode it.
    if !strings.Contains(caPEM, "-----BEGIN") {
        // Remove whitespace/newlines for robust decoding.
        compact := strings.Map(func(r rune) rune {
            switch r {
            case ' ', '\n', '\r', '\t':
                return -1
            default:
                return r
            }
        }, caPEM)
        if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
            caPEM = string(decoded)
        }
    }

    // Indent cert lines by 4 spaces under the YAML block scalar.
    var indented strings.Builder
    for _, line := range strings.Split(caPEM, "\n") {
        indented.WriteString("    ")
        indented.WriteString(line)
        indented.WriteString("\n")
    }

    trustedRoots := strings.Builder{}
    trustedRoots.WriteString("---\n")
    trustedRoots.WriteString("apiVersion: v1alpha1\n")
    trustedRoots.WriteString("kind: TrustedRootsConfig\n")
    trustedRoots.WriteString("name: custom-ca\n")
    trustedRoots.WriteString("certificates: |-\n")
    trustedRoots.WriteString(indented.String())
    out += trustedRoots.String()

    return out
}

// findVMByNameAnywhere searches the entire vCenter inventory for a VM with the given name.
func (p *Provisioner) findVMByNameAnywhere(ctx context.Context, name string) (*object.VirtualMachine, error) {
    m := view.NewManager(p.vsphereClient.Client)

    v, err := m.CreateContainerView(ctx, p.vsphereClient.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
    if err != nil {
        return nil, fmt.Errorf("failed to create container view: %w", err)
    }
    defer func() { _ = v.Destroy(ctx) }()

    var vms []mo.VirtualMachine
    if err := v.Retrieve(ctx, []string{"VirtualMachine"}, []string{"name"}, &vms); err != nil {
        return nil, fmt.Errorf("failed to retrieve VMs from view: %w", err)
    }

    for i := range vms {
        if vms[i].Name == name {
            vm := object.NewVirtualMachine(p.vsphereClient.Client, vms[i].Reference())
            return vm, nil
        }
    }

    // Secondary attempt: use Finder to list all VMs and match by name
    finder := find.NewFinder(p.vsphereClient.Client, true)
    all, ferr := finder.VirtualMachineList(ctx, "*")
    if ferr == nil {
        for _, cand := range all {
            if cand != nil {
                if refName, nerr := cand.ObjectName(ctx); nerr == nil && refName == name {
                    return cand, nil
                }
            }
        }
    }

    return nil, fmt.Errorf("vm '%s' not found anywhere", name)
}

// NewProvisioner creates a new provisioner.
func NewProvisioner(vsphereClient *govmomi.Client, logger *zap.Logger) *Provisioner {
	return &Provisioner{
		vsphereClient: vsphereClient,
		logger:        logger,
	}
}

// ProvisionSteps implements infra.Provisioner.
func (p *Provisioner) ProvisionSteps() []provision.Step[*resources.Machine] {
	return []provision.Step[*resources.Machine]{
		provision.NewStep("createSchematic", func(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
			_, err := pctx.GenerateSchematicID(ctx, logger,
				provision.WithExtraKernelArgs("console=ttyS0,38400n8"),
				provision.WithoutConnectionParams(),
			)
			if err != nil {
				return err
			}

			return nil
		}),
		provision.NewStep("ensureVM", p.ensureVM),
	}
}

// DeprovisionSteps implements infra.Provisioner.
func (p *Provisioner) DeprovisionSteps() []provision.Step[*resources.Machine] {
	return []provision.Step[*resources.Machine]{
		provision.NewStep("destroyVM", p.destroyVM),
	}
}

//nolint:gocognit,gocyclo,cyclop // provisioning flow spans multiple steps; acceptable complexity for now.
func (p *Provisioner) ensureVM(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
	var data Data
	if err := pctx.UnmarshalProviderData(&data); err != nil {
		return fmt.Errorf("failed to unmarshal provider data: %w", err)
	}

	// Use the correct pattern from Terraform provider
	finder := find.NewFinder(p.vsphereClient.Client, true)

	dc, err := finder.Datacenter(ctx, data.Datacenter)
	if err != nil {
		return fmt.Errorf("failed to find datacenter %s: %w", data.Datacenter, err)
	}

	// Critical: must reassign the result of SetDatacenter
	finder = finder.SetDatacenter(dc)

	cluster, err := finder.ClusterComputeResource(ctx, data.Cluster)
	if err != nil {
		return fmt.Errorf("failed to find cluster %s: %w", data.Cluster, err)
	}

	ds, err := finder.Datastore(ctx, data.Datastore)
	if err != nil {
		return fmt.Errorf("failed to find datastore %s: %w", data.Datastore, err)
	}

	network, err := finder.Network(ctx, data.PortGroup)
	if err != nil {
		return fmt.Errorf("failed to find network %s: %w", data.PortGroup, err)
	}

	// Determine deployment method
	useContentLibrary := data.ContentLibrary != "" && data.ContentLibraryItem != ""

	var templateVM *object.VirtualMachine

	if !useContentLibrary {
		// Only look for template VM if not using Content Library
		if data.Template == "" {
			return fmt.Errorf("either template or content_library+content_library_item must be specified")
		}

		templateVM, err = finder.VirtualMachine(ctx, data.Template)
		if err != nil {
			return fmt.Errorf("failed to find template VM %s: %w", data.Template, err)
		}
	}

	vm, err := finder.VirtualMachine(ctx, pctx.GetRequestID())
	if err != nil && err.Error() != "vm '"+pctx.GetRequestID()+"' not found" {
		return fmt.Errorf("failed to check for existing VM %s: %w", pctx.GetRequestID(), err)
	}

	if vm != nil {
		var mvm mo.VirtualMachine

		pc := property.DefaultCollector(p.vsphereClient.Client)
		if propErr := pc.RetrieveOne(ctx, vm.Reference(), []string{"summary"}, &mvm); propErr != nil {
			return fmt.Errorf("failed to retrieve VM summary: %w", propErr)
		}

		if mvm.Summary.Runtime.PowerState == types.VirtualMachinePowerStatePoweredOn {
			if mvm.Summary.Guest.IpAddress != "" {
				pctx.State.TypedSpec().Value.ManagementAddress = mvm.Summary.Guest.IpAddress
				logger.Info("machine is ready", zap.String("ip", mvm.Summary.Guest.IpAddress))

				return nil
			}

			logger.Info("VM is powered on but has no IP yet, waiting...")

			return provision.NewRetryInterval(10 * time.Second)
		}

		logger.Info("VM exists but is not powered on, powering on...")

		powerOnTask, pErr := vm.PowerOn(ctx)
		if pErr != nil {
			return fmt.Errorf("failed to power on VM: %w", pErr)
		}

		if wErr := powerOnTask.Wait(ctx); wErr != nil {
			return fmt.Errorf("failed to wait for power on task: %w", wErr)
		}

		return provision.NewRetryInterval(10 * time.Second)
	}

	// VM doesn't exist, so we need to create it.
	if useContentLibrary {
		logger.Info("creating new VM from Content Library", zap.String("library", data.ContentLibrary), zap.String("item", data.ContentLibraryItem))

		// Deploy directly from Content Library
		err = p.deployFromContentLibrary(ctx, pctx.GetRequestID(), cluster, ds, network, data.ContentLibrary, data.ContentLibraryItem, pctx)
		if err != nil {
			return fmt.Errorf("failed to deploy VM from Content Library: %w", err)
		}
	} else {
		logger.Info("creating new VM from template")

		cloneSpec, folder, err := p.createCloneSpec(ctx, pctx, data, cluster, ds, network, templateVM)
		if err != nil {
			return err
		}

		task, cloneErr := templateVM.Clone(ctx, folder, pctx.GetRequestID(), *cloneSpec)
		if cloneErr != nil {
			return fmt.Errorf("failed to clone VM: %w", cloneErr)
		}

		if waitErr := task.Wait(ctx); waitErr != nil {
			return fmt.Errorf("failed to wait for clone task: %w", waitErr)
		}

		logger.Info("VM cloned successfully, configuring VM")

		// Need to find the newly created VM to configure it
		newVM, err := finder.VirtualMachine(ctx, pctx.GetRequestID())
		if err != nil {
			return fmt.Errorf("failed to find newly created VM %s: %w", pctx.GetRequestID(), err)
		}

		// Configure VM before powering on (disk resize, advanced parameters)
		if configErr := p.configureVM(ctx, newVM, data, pctx); configErr != nil {
			return fmt.Errorf("failed to configure VM: %w", configErr)
		}

		logger.Info("VM configured successfully, powering on")

		powerOnTask, pErr := newVM.PowerOn(ctx)
		if pErr != nil {
			return fmt.Errorf("failed to power on VM: %w", pErr)
		}

		if wErr := powerOnTask.Wait(ctx); wErr != nil {
			return fmt.Errorf("failed to wait for power on task: %w", wErr)
		}
	}

	return provision.NewRetryInterval(10 * time.Second)
}

// configureVM configures a VM after cloning but before powering on.
func (p *Provisioner) configureVM(ctx context.Context, vm *object.VirtualMachine, data Data, pctx provision.Context[*resources.Machine]) error {
	// Get current VM configuration
	var vmProps mo.VirtualMachine

	err := vm.Properties(ctx, vm.Reference(), []string{"config"}, &vmProps)
	if err != nil {
		return fmt.Errorf("failed to get VM properties: %w", err)
	}

	// Prepare configuration spec
	configSpec := types.VirtualMachineConfigSpec{}

	// Configure CPU and Memory if specified
	if data.CPUs > 0 {
		configSpec.NumCPUs = data.CPUs
	}

	if data.MemoryMB > 0 {
		configSpec.MemoryMB = data.MemoryMB
	}

	// Configure disk size (minimum 10GB)
	if vmProps.Config != nil && len(vmProps.Config.Hardware.Device) > 0 {
		for _, device := range vmProps.Config.Hardware.Device {
			if disk, ok := device.(*types.VirtualDisk); ok {
				// Convert to GB and check minimum size
				currentSizeGB := disk.CapacityInKB / (1024 * 1024)
				minSizeGB := int64(10)

				if currentSizeGB < minSizeGB {
					// Resize disk to minimum 10GB
					disk.CapacityInKB = minSizeGB * 1024 * 1024

					deviceChange := &types.VirtualDeviceConfigSpec{
						Operation: types.VirtualDeviceConfigSpecOperationEdit,
						Device:    disk,
					}
					configSpec.DeviceChange = append(configSpec.DeviceChange, deviceChange)

					p.logger.Info("resizing VM disk", zap.Int64("currentGB", currentSizeGB), zap.Int64("newGB", minSizeGB))
				}

				break // Only resize the first disk
			}
		}
	}

	// Enable EFI Secure Boot if requested
	if data.SecureBoot {
		configSpec.Firmware = "efi"
		sb := true
		configSpec.BootOptions = &types.VirtualMachineBootOptions{EfiSecureBootEnabled: &sb}
	}

	// Set advanced parameters for Talos: single base64-encoded key
	    // Build JoinConfig with optional CA and hostname injection.
    joinCfg := buildJoinConfigWithOptionalAdditions(pctx.ConnectionParams.JoinConfig, pctx.GetRequestID())

    configSpec.ExtraConfig = []types.BaseOptionValue{
        &types.OptionValue{
            Key:   "disk.enableUUID",
            Value: "1",
        },
        &types.OptionValue{
            Key:   "guestinfo.talos.config",
            Value: base64.StdEncoding.EncodeToString([]byte(joinCfg)),
        },
    }

	// Apply the configuration
	task, err := vm.Reconfigure(ctx, configSpec)
	if err != nil {
		return fmt.Errorf("failed to reconfigure VM: %w", err)
	}

	err = task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for VM reconfiguration: %w", err)
	}

	p.logger.Info("VM configured successfully", zap.String("vm", vm.Name()))

	return nil
}

// deployFromContentLibrary deploys a VM from a Content Library item.
//
//nolint:gocognit,gocyclo,cyclop // content library deployment covers many branches; refactor later if needed.
func (p *Provisioner) deployFromContentLibrary(
	ctx context.Context,
	requestID string,
	cluster *object.ClusterComputeResource,
	ds *object.Datastore,
	network object.NetworkReference,
	libraryName string,
	itemName string,
	pctx provision.Context[*resources.Machine],
) error {
	// Initialize REST client and authenticate.
	restClient := rest.NewClient(p.vsphereClient.Client)

	loggedIn := false

	// 1) Try credentials embedded in the SOAP client's URL, if present.
	restURL := *p.vsphereClient.URL()
	if restURL.User != nil {
		triedUser := restURL.User.Username()
		p.logger.Info("performing REST login via URL creds", zap.String("user", triedUser))
		if err := restClient.Login(ctx, restURL.User); err == nil {
			loggedIn = true
		} else {
			p.logger.Warn("REST login via URL creds failed", zap.String("user", triedUser), zap.Error(err))
		}
	}

	// 2) Fall back to environment variables (as used by main), if available.
	if !loggedIn {
		envUser := os.Getenv("VSPHERE_USERNAME")
		envPass := os.Getenv("VSPHERE_PASSWORD")
		if envUser != "" && envPass != "" {
			p.logger.Info("performing REST login via environment creds", zap.String("user", envUser))
			if err := restClient.Login(ctx, url.UserPassword(envUser, envPass)); err == nil {
				loggedIn = true
			} else {
				return fmt.Errorf("failed REST login via env creds: %w", err)
			}
		}
	}

	if !loggedIn {
		return fmt.Errorf("failed REST login: no credentials available in SOAP URL or environment")
	}

	libMgr := library.NewManager(restClient)
	// Find the content library by name
	libs, err := libMgr.GetLibraries(ctx)
	if err != nil {
		return fmt.Errorf("failed to list content libraries: %w", err)
	}

	var libID string

	for _, lib := range libs {
		if lib.Name == libraryName {
			libID = lib.ID

			break
		}
	}

	if libID == "" {
		return fmt.Errorf("content library %q not found", libraryName)
	}

	// Find the item by name within the library
	items, err := libMgr.GetLibraryItems(ctx, libID)
	if err != nil {
		return fmt.Errorf("failed to list items in library %q: %w", libraryName, err)
	}

	var item *library.Item

	for i := range items {
		if items[i].Name == itemName {
			item = &items[i]

			break
		}
	}

	if item == nil {
		return fmt.Errorf("content library item %q not found in library %q", itemName, libraryName)
	}

	// Resolve placement
	rp, err := cluster.ResourcePool(ctx)
	if err != nil {
		return fmt.Errorf("failed to get resource pool: %w", err)
	}

	rpID := rp.Reference().Value
	dsID := ds.Reference().Value
	netID := network.Reference().Value

	vcenterMgr := vcenter.NewManager(restClient)

	// Deploy according to item type
	var vmRef *types.ManagedObjectReference

	switch item.Type {
	case library.ItemTypeOVF:
		// Try to fetch OVF networks and map all to the selected port group
		var nets []string
		if fr, ferr := vcenterMgr.FilterLibraryItem(ctx, item.ID, vcenter.FilterRequest{Target: vcenter.Target{ResourcePoolID: rpID}}); ferr == nil {
			nets = fr.Networks
		}

		var mappings []vcenter.NetworkMapping
		for _, n := range nets {
			mappings = append(mappings, vcenter.NetworkMapping{Key: n, Value: netID})
		}

		deploy := vcenter.Deploy{
			DeploymentSpec: vcenter.DeploymentSpec{
				Name:               requestID,
				AcceptAllEULA:      true,
				DefaultDatastoreID: dsID,
				NetworkMappings:    mappings,
			},
			Target: vcenter.Target{
				ResourcePoolID: rpID,
			},
		}

		vmRef, err = vcenterMgr.DeployLibraryItem(ctx, item.ID, deploy)
		if err != nil {
			return fmt.Errorf("failed to deploy OVF item: %w", err)
		}
	case library.ItemTypeVMTX:
		placement := &library.Placement{ResourcePool: rpID}
		deploy := vcenter.DeployTemplate{
			Name:          requestID,
			Placement:     placement,
			PoweredOn:     false,
			DiskStorage:   &vcenter.DiskStorage{Datastore: dsID},
			VMHomeStorage: &vcenter.DiskStorage{Datastore: dsID},
		}

		vmRef, err = vcenterMgr.DeployTemplateLibraryItem(ctx, item.ID, deploy)
		if err != nil {
			return fmt.Errorf("failed to deploy VMTX item: %w", err)
		}
	default:
		return fmt.Errorf("unsupported content library item type: %s", item.Type)
	}

	// Locate VM and configure it
	vm := object.NewVirtualMachine(p.vsphereClient.Client, *vmRef)

	// Ensure NIC is connected to the selected network (especially important for VMTX)
	if network != nil {
		devices, devErr := vm.Device(ctx)
		if devErr != nil {
			return fmt.Errorf("failed to get VM devices: %w", devErr)
		}

		nets := devices.SelectByType((*types.VirtualEthernetCard)(nil))
		if len(nets) > 0 {
			if nic, ok := nets[0].(types.BaseVirtualEthernetCard); ok {
				backing, err := network.EthernetCardBackingInfo(ctx)
				if err != nil {
					return fmt.Errorf("failed to get network backing info: %w", err)
				}

				netCard := nic.GetVirtualEthernetCard()
				netCard.Backing = backing

				devChange := &types.VirtualDeviceConfigSpec{
					Operation: types.VirtualDeviceConfigSpecOperationEdit,
					Device:    netCard,
				}

				reconfigTask, recErr := vm.Reconfigure(ctx, types.VirtualMachineConfigSpec{DeviceChange: []types.BaseVirtualDeviceConfigSpec{devChange}})
				if recErr != nil {
					return fmt.Errorf("failed to reconfigure VM: %w", recErr)
				}

				if wErr := reconfigTask.Wait(ctx); wErr != nil {
					p.logger.Warn("failed to wait for NIC reconfigure task", zap.Error(wErr))
				}
			}
		}
	}

	// Configure VM (CPU/memory, disk min size, talos guestinfo, secure boot)
	// Build Data from pctx to pass values
	var data Data
	if dataErr := pctx.UnmarshalProviderData(&data); dataErr != nil {
		return fmt.Errorf("failed to unmarshal provider data for configuration: %w", dataErr)
	}

	if cfgErr := p.configureVM(ctx, vm, data, pctx); cfgErr != nil {
		return fmt.Errorf("failed to configure VM post-deploy: %w", cfgErr)
	}

	// Power on the VM
	powerOnTask, pErr := vm.PowerOn(ctx)
	if pErr != nil {
		return fmt.Errorf("failed to power on VM: %w", pErr)
	}

	if wErr := powerOnTask.Wait(ctx); wErr != nil {
		return fmt.Errorf("failed waiting for power on: %w", wErr)
	}

	return nil
}

// destroyVM destroys the VM during deprovisioning.
func (p *Provisioner) destroyVM(ctx context.Context, logger *zap.Logger, pctx provision.Context[*resources.Machine]) error {
	var data Data
	if err := pctx.UnmarshalProviderData(&data); err != nil {
		return fmt.Errorf("failed to unmarshal provider data: %w", err)
	}

	logger.Info("deprovisioning VM", zap.String("vm_id", pctx.GetRequestID()), zap.String("datacenter", data.Datacenter))

	if data.Datacenter == "" {
		return fmt.Errorf("datacenter field is empty in provider data")
	}

	// Use the correct pattern from Terraform provider
	finder := find.NewFinder(p.vsphereClient.Client, true)

	dc, err := finder.Datacenter(ctx, data.Datacenter)
	if err != nil {
		return fmt.Errorf("failed to find datacenter %s: %w", data.Datacenter, err)
	}

	// Critical: must reassign the result of SetDatacenter
	finder = finder.SetDatacenter(dc)

	vm, err := finder.VirtualMachine(ctx, pctx.GetRequestID())
	if err != nil {
		if err.Error() == "vm '"+pctx.GetRequestID()+"' not found" {
			logger.Info("VM not found in datacenter, attempting global inventory search", zap.String("vm", pctx.GetRequestID()))

			// Fallback: search anywhere in inventory by name
			vm, err = p.findVMByNameAnywhere(ctx, pctx.GetRequestID())
			if err != nil {
				logger.Info("VM not found across inventory; treating as already deleted", zap.String("vm", pctx.GetRequestID()))

				return nil
			}
		} else {
			return fmt.Errorf("failed to find VM %s for deprovisioning: %w", pctx.GetRequestID(), err)
		}
	}

	logger.Info("destroying VM", zap.String("vm", pctx.GetRequestID()))

	// Power off VM if it's running
	var vmProps mo.VirtualMachine

	pc := property.DefaultCollector(p.vsphereClient.Client)
	if propErr := pc.RetrieveOne(ctx, vm.Reference(), []string{"summary"}, &vmProps); propErr != nil {
		logger.Warn("failed to retrieve VM power state, proceeding with destruction", zap.Error(propErr))
	} else if vmProps.Summary.Runtime.PowerState == types.VirtualMachinePowerStatePoweredOn {
		logger.Info("powering off VM before destruction")

		powerOffTask, pErr := vm.PowerOff(ctx)
		if pErr != nil {
			logger.Warn("failed to power off VM, proceeding with destruction", zap.Error(pErr))
		} else {
			if wErr := powerOffTask.Wait(ctx); wErr != nil {
				logger.Warn("failed to wait for power off, proceeding with destruction", zap.Error(wErr))
			}
		}
	}

	// Destroy the VM
	destroyTask, err := vm.Destroy(ctx)
	if err != nil {
		return fmt.Errorf("failed to destroy VM: %w", err)
	}

	if err := destroyTask.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait for VM destruction: %w", err)
	}

	logger.Info("VM destroyed successfully", zap.String("vm", pctx.GetRequestID()))

	return nil
}

func (p *Provisioner) createCloneSpec(
	ctx context.Context, pctx provision.Context[*resources.Machine], data Data,
	cluster *object.ClusterComputeResource, ds *object.Datastore, network object.NetworkReference, templateVM *object.VirtualMachine,
) (*types.VirtualMachineCloneSpec, *object.Folder, error) {
	pool, err := cluster.ResourcePool(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get resource pool: %w", err)
	}

	poolRef := pool.Reference()
	relocateSpec := types.VirtualMachineRelocateSpec{
		Pool:      &poolRef,
		Datastore: types.NewReference(ds.Reference()),
	}

	deviceChanges, err := getDeviceChanges(ctx, templateVM, network, int32(data.DiskGiB))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get device changes: %w", err)
	}

	    // Build JoinConfig with optional CA and hostname injection.
    joinCfg := buildJoinConfigWithOptionalAdditions(pctx.ConnectionParams.JoinConfig, pctx.GetRequestID())

    config := types.VirtualMachineConfigSpec{
        NumCPUs:      data.CPUs,
        MemoryMB:     data.MemoryMB,
        DeviceChange: deviceChanges,
        ExtraConfig: []types.BaseOptionValue{
            &types.OptionValue{
                Key:   "disk.enableUUID",
                Value: "1",
            },
            &types.OptionValue{
                Key:   "guestinfo.talos.config",
                Value: base64.StdEncoding.EncodeToString([]byte(joinCfg)),
            },
        },
    }

	// Enable EFI Secure Boot if requested
	if data.SecureBoot {
		// Set firmware to EFI and enable secure boot
		config.Firmware = "efi"
		sb := true
		config.BootOptions = &types.VirtualMachineBootOptions{EfiSecureBootEnabled: &sb}
	}

	cloneSpec := types.VirtualMachineCloneSpec{
		Location: relocateSpec,
		PowerOn:  false,
		Template: false,
		Config:   &config,
	}

	finder := find.NewFinder(p.vsphereClient.Client)

	dc, err := finder.Datacenter(ctx, data.Datacenter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find datacenter %s: %w", data.Datacenter, err)
	}

	dcFolders, err := dc.Folders(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get datacenter folders: %w", err)
	}

	return &cloneSpec, dcFolders.VmFolder, nil
}

// Deprovision implements infra.Provisioner.
func (p *Provisioner) Deprovision(ctx context.Context, logger *zap.Logger, state *resources.Machine, machineRequest *infra.MachineRequest) error {
    // Some controllers may call this direct path instead of step-based flow.
    if machineRequest == nil {
        if logger != nil {
            logger.Warn("machineRequest is nil; nothing to deprovision")
        }
        return nil
    }

    vmName := machineRequest.Metadata().ID()
    if logger != nil {
        logger.Info("direct deprovision invoked; attempting global VM deletion", zap.String("vm_id", vmName))
    }

    // Locate the VM anywhere in inventory by name.
    vm, err := p.findVMByNameAnywhere(ctx, vmName)
    if err != nil {
        if logger != nil {
            logger.Info("VM not found across inventory; treating as already deleted", zap.String("vm", vmName))
        }
        return nil
    }

    // Power off if needed, then destroy.
    var vmProps mo.VirtualMachine
    pc := property.DefaultCollector(p.vsphereClient.Client)
    if propErr := pc.RetrieveOne(ctx, vm.Reference(), []string{"summary"}, &vmProps); propErr != nil {
        if logger != nil {
            logger.Warn("failed to retrieve VM power state, proceeding with destruction", zap.Error(propErr))
        }
    } else if vmProps.Summary.Runtime.PowerState == types.VirtualMachinePowerStatePoweredOn {
        if logger != nil {
            logger.Info("powering off VM before destruction", zap.String("vm", vmName))
        }
        if powerOffTask, poErr := vm.PowerOff(ctx); poErr != nil {
            if logger != nil {
                logger.Warn("failed to power off VM, proceeding with destruction", zap.Error(poErr))
            }
        } else if wErr := powerOffTask.Wait(ctx); wErr != nil {
            if logger != nil {
                logger.Warn("failed to wait for power off, proceeding with destruction", zap.Error(wErr))
            }
        }
    }

    destroyTask, derr := vm.Destroy(ctx)
    if derr != nil {
        return fmt.Errorf("failed to destroy VM: %w", derr)
    }
    if err := destroyTask.Wait(ctx); err != nil {
        return fmt.Errorf("failed to wait for VM destruction: %w", err)
    }

    if logger != nil {
        logger.Info("VM destroyed successfully", zap.String("vm", vmName))
    }

    return nil
}

// getDeviceChanges prepares the device specifications for network and disk for the VM clone operation.
func getDeviceChanges(ctx context.Context, templateVM *object.VirtualMachine, network object.NetworkReference, diskGiB int32) ([]types.BaseVirtualDeviceConfigSpec, error) {
	var (
		devices object.VirtualDeviceList
		err     error
	)

	devices, err = templateVM.Device(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get template devices: %w", err)
	}

	var deviceChanges []types.BaseVirtualDeviceConfigSpec

	// Handle network device
	netDevices := devices.SelectByType((*types.VirtualEthernetCard)(nil))
	if len(netDevices) == 0 {
		return nil, fmt.Errorf("no network device found on template")
	}

	netDevice := netDevices[0]

	backing, err := network.EthernetCardBackingInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network backing info: %w", err)
	}

	netCard, ok := netDevice.(types.BaseVirtualEthernetCard)
	if !ok {
		return nil, fmt.Errorf("failed to assert network device type")
	}

	concreteCard := netCard.GetVirtualEthernetCard()
	concreteCard.Backing = backing

	deviceChanges = append(deviceChanges, &types.VirtualDeviceConfigSpec{
		Operation: types.VirtualDeviceConfigSpecOperationEdit,
		Device:    concreteCard,
	})

	// Handle disk resizing
	if diskGiB > 0 {
		disks := devices.SelectByType((*types.VirtualDisk)(nil))
		if len(disks) == 0 {
			return nil, fmt.Errorf("no disk found on template")
		}

		disk, ok := disks[0].(*types.VirtualDisk)
		if !ok {
			return nil, fmt.Errorf("failed to assert disk device type")
		}

		disk.CapacityInKB = int64(diskGiB) * 1024 * 1024
		deviceChanges = append(deviceChanges, &types.VirtualDeviceConfigSpec{
			Operation: types.VirtualDeviceConfigSpecOperationEdit,
			Device:    disk,
		})
	}

	return deviceChanges, nil
}
