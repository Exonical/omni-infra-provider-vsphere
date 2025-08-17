// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provider

// Data is the provider custom machine config.
type Data struct {
	Datacenter         string `yaml:"datacenter"`
	Datastore          string `yaml:"datastore"`
	Cluster            string `yaml:"cluster"`
	PortGroup          string `yaml:"port_group"`
	Template           string `yaml:"template"`
	ContentLibrary     string `yaml:"content_library"`
	ContentLibraryItem string `yaml:"content_library_item"`
	MemoryMB           int64  `yaml:"memory_mb"`
	DiskGiB            int64  `yaml:"disk_gib"`
	CPUs               int32  `yaml:"cpus"`
	SecureBoot         bool   `yaml:"secure_boot"`
}
