// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package resources contains resources stored in the vSphere infra provider state.
package resources

import (
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/resource/typed"
	specs "github.com/siderolabs/omni/client/api/omni/specs"
	"github.com/siderolabs/omni/client/pkg/infra"

	providermeta "github.com/siderolabs/omni-infra-provider-vsphere/internal/pkg/provider/meta"
)

// MachineSpec wraps specs.MachineSpec.
type MachineSpec = protobuf.ResourceSpec[specs.MachineSpec, *specs.MachineSpec]

// MachineExtension provides auxiliary methods for Machine resource.
type MachineExtension struct{}

// ResourceDefinition implements [typed.Extension] interface.
func (e *MachineExtension) ResourceDefinition() meta.ResourceDefinitionSpec {
	return meta.ResourceDefinitionSpec{
		Type:             infra.ResourceType("Machine", providermeta.ProviderID),
		Aliases:          []resource.Type{},
		DefaultNamespace: infra.ResourceNamespace(providermeta.ProviderID),
		PrintColumns:     []meta.PrintColumn{},
	}
}

// Machine describes a machine configuration.
type Machine struct {
	*typed.Resource[MachineSpec, *MachineExtension]
}

// NewMachine creates a new Machine resource.
func NewMachine() *Machine {
	return &Machine{
		Resource: typed.NewResource[MachineSpec, *MachineExtension](
			resource.NewMetadata("", infra.ResourceType("Machine", providermeta.ProviderID), "", resource.VersionUndefined),
			protobuf.NewResourceSpec(&specs.MachineSpec{}),
		),
	}
}

// New creates a new Machine resource - satisfies infra.RD interface.
func (*Machine) New() resource.Resource {
	return NewMachine()
}

// DeepCopy implements resource.Resource.
func (m *Machine) DeepCopy() resource.Resource {
	if m == nil {
		return nil
	}
	// DeepCopy returns resource.Resource; ensure type assertion is safe
	cp := m.Resource.DeepCopy()
	if tr, ok := cp.(*typed.Resource[MachineSpec, *MachineExtension]); ok {
		return &Machine{Resource: tr}
	}

	// Fallback to a fresh resource if assertion fails
	return NewMachine()
}

// ResourceDefinition implements part of [resource.Resource] interface.
func (m *Machine) ResourceDefinition() meta.ResourceDefinitionSpec {
	return (&MachineExtension{}).ResourceDefinition()
}

// UnmarshalProto ensures the embedded typed resource is initialized and delegates to it.
func (m *Machine) UnmarshalProto(md *resource.Metadata, b []byte) error {
	if m.Resource == nil {
		m.Resource = typed.NewResource[MachineSpec, *MachineExtension](
			resource.NewMetadata("", infra.ResourceType("Machine", providermeta.ProviderID), "", resource.VersionUndefined),
			protobuf.NewResourceSpec(&specs.MachineSpec{}),
		)
	}

	return m.Resource.UnmarshalProto(md, b)
}

// ensureInit lazily initializes the embedded typed.Resource if nil.
func (m *Machine) ensureInit() {
	if m.Resource == nil {
		m.Resource = typed.NewResource[MachineSpec, *MachineExtension](
			resource.NewMetadata("", infra.ResourceType("Machine", providermeta.ProviderID), "", resource.VersionUndefined),
			protobuf.NewResourceSpec(&specs.MachineSpec{}),
		)
	}
}

// Metadata returns a non-nil metadata, initializing the resource if needed.
func (m *Machine) Metadata() *resource.Metadata {
	m.ensureInit()
	return m.Resource.Metadata()
}

// TypedSpec returns the typed spec, initializing the resource if needed.
func (m *Machine) TypedSpec() *MachineSpec {
    m.ensureInit()
    return m.Resource.TypedSpec()
}
