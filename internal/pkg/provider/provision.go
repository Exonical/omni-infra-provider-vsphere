// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package provider implements vSphere infra provider core.
package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/siderolabs/omni/client/pkg/infra/provision"
	"github.com/siderolabs/omni/client/pkg/omni/resources/infra"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
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
		if err := pc.RetrieveOne(ctx, vm.Reference(), []string{"summary"}, &mvm); err != nil {
			return fmt.Errorf("failed to retrieve VM summary: %w", err)
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
		task, err := vm.PowerOn(ctx)
		if err != nil {
			return fmt.Errorf("failed to power on VM: %w", err)
		}
		if err := task.Wait(ctx); err != nil {
			return fmt.Errorf("failed to wait for power on task: %w", err)
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

		task, err := templateVM.Clone(ctx, folder, pctx.GetRequestID(), *cloneSpec)
		if err != nil {
			return fmt.Errorf("failed to clone VM: %w", err)
		}

		if err := task.Wait(ctx); err != nil {
			return fmt.Errorf("failed to wait for clone task: %w", err)
		}

		logger.Info("VM cloned successfully, configuring VM")

		// Need to find the newly created VM to configure it
		newVM, err := finder.VirtualMachine(ctx, pctx.GetRequestID())
		if err != nil {
			return fmt.Errorf("failed to find newly created VM %s: %w", pctx.GetRequestID(), err)
		}

		// Configure VM before powering on (disk resize, advanced parameters)
		if err := p.configureVM(ctx, newVM, data, pctx); err != nil {
			return fmt.Errorf("failed to configure VM: %w", err)
		}

		logger.Info("VM configured successfully, powering on")

		powerOnTask, err := newVM.PowerOn(ctx)
		if err != nil {
			return fmt.Errorf("failed to power on VM: %w", err)
		}

		if err := powerOnTask.Wait(ctx); err != nil {
			return fmt.Errorf("failed to wait for power on task: %w", err)
		}
	}

	return provision.NewRetryInterval(10 * time.Second)
}

// configureVM configures a VM after cloning but before powering on
func (p *Provisioner) configureVM(ctx context.Context, vm *object.VirtualMachine, data Data, pctx provision.Context[*resources.Machine]) error {
	// Get current VM configuration
	var vmProps mo.VirtualMachine
	err := vm.Properties(ctx, vm.Reference(), []string{"config"}, &vmProps)
	if err != nil {
		return fmt.Errorf("failed to get VM properties: %w", err)
	}
	
	// Prepare configuration spec
	configSpec := types.VirtualMachineConfigSpec{}
	
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
	
	// Set advanced parameters for Talos
	configSpec.ExtraConfig = []types.BaseOptionValue{
		&types.OptionValue{
			Key:   "disk.enableUUID",
			Value: "1",
		},
		&types.OptionValue{
			Key:   "guestinfo.talos.config",
			Value: base64.StdEncoding.EncodeToString([]byte(pctx.ConnectionParams.JoinConfig)),
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

// deployFromContentLibrary deploys a VM from a Content Library item
func (p *Provisioner) deployFromContentLibrary(ctx context.Context, requestID string, cluster *object.ClusterComputeResource, ds *object.Datastore, network object.NetworkReference, libraryName, itemName string, pctx provision.Context[*resources.Machine]) error {
	// For now, return an error since Content Library deployment is complex
	// This will be implemented in a future update
	return fmt.Errorf("Content Library deployment not yet implemented - please use template-based deployment")
}

// destroyVM destroys the VM during deprovisioning
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
			logger.Info("VM already deleted or does not exist")
			return nil
		}
		return fmt.Errorf("failed to find VM %s for deprovisioning: %w", pctx.GetRequestID(), err)
	}

	logger.Info("destroying VM", zap.String("vm", pctx.GetRequestID()))

	// Power off VM if it's running
	var vmProps mo.VirtualMachine
	pc := property.DefaultCollector(p.vsphereClient.Client)
	if err := pc.RetrieveOne(ctx, vm.Reference(), []string{"summary"}, &vmProps); err != nil {
		logger.Warn("failed to retrieve VM power state, proceeding with destruction", zap.Error(err))
	} else if vmProps.Summary.Runtime.PowerState == types.VirtualMachinePowerStatePoweredOn {
		logger.Info("powering off VM before destruction")
		powerOffTask, err := vm.PowerOff(ctx)
		if err != nil {
			logger.Warn("failed to power off VM, proceeding with destruction", zap.Error(err))
		} else {
			if err := powerOffTask.Wait(ctx); err != nil {
				logger.Warn("failed to wait for power off, proceeding with destruction", zap.Error(err))
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

func (p *Provisioner) createCloneSpec(ctx context.Context, pctx provision.Context[*resources.Machine], data Data, cluster *object.ClusterComputeResource, ds *object.Datastore, network object.NetworkReference, templateVM *object.VirtualMachine) (*types.VirtualMachineCloneSpec, *object.Folder, error) {
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

	config := types.VirtualMachineConfigSpec{
		NumCPUs:      data.CPUs,
		MemoryMB:     data.MemoryMB,
		DeviceChange: deviceChanges,
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{
				Key:   "guestinfo.metadata",
				Value: base64.StdEncoding.EncodeToString([]byte(pctx.ConnectionParams.JoinConfig)),
			},
			&types.OptionValue{
				Key:   "guestinfo.metadata.encoding",
				Value: "base64",
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
	// For now, return a helpful error message since the step-based approach already works correctly
	// The main issue is accessing provider data from the machine state in the direct Deprovision method
	// The step-based deprovisioning in DeprovisionSteps() already has proper datacenter context handling
	return fmt.Errorf("use step-based deprovisioning - DeprovisionSteps() already implements correct datacenter context handling")
}

// getDeviceChanges prepares the device specifications for network and disk for the VM clone operation.
func getDeviceChanges(ctx context.Context, templateVM *object.VirtualMachine, network object.NetworkReference, diskGiB int32) ([]types.BaseVirtualDeviceConfigSpec, error) {
	var devices object.VirtualDeviceList
	var err error

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

	netCard := netDevice.(types.BaseVirtualEthernetCard).GetVirtualEthernetCard()
	netCard.Backing = backing

	deviceChanges = append(deviceChanges, &types.VirtualDeviceConfigSpec{
		Operation: types.VirtualDeviceConfigSpecOperationEdit,
		Device:    netCard,
	})

	// Handle disk resizing
	if diskGiB > 0 {
		disks := devices.SelectByType((*types.VirtualDisk)(nil))
		if len(disks) == 0 {
			return nil, fmt.Errorf("no disk found on template")
		}
		disk := disks[0].(*types.VirtualDisk)
		disk.CapacityInKB = int64(diskGiB) * 1024 * 1024
		deviceChanges = append(deviceChanges, &types.VirtualDeviceConfigSpec{
			Operation: types.VirtualDeviceConfigSpecOperationEdit,
			Device:    disk,
		})
	}

	return deviceChanges, nil
}
