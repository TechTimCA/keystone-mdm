package wmdm

import "github.com/TechTimCA/keystone-mdm/internal/store"

// Inventory lists the OMA-URIs Keystone reads from every PC.
var Inventory = []struct{ Label, URI string }{
	{"Computer name", "./DevDetail/Ext/Microsoft/DeviceName"},
	{"Manufacturer", "./DevInfo/Man"},
	{"Model", "./DevInfo/Mod"},
	{"Windows version", "./DevDetail/SwV"},
	{"Windows edition", "./DevDetail/Ext/Microsoft/OSPlatform"},
	{"Serial number", "./DevDetail/Ext/Microsoft/SMBIOSSerialNumber"},
	{"Memory (MB)", "./DevDetail/Ext/Microsoft/TotalRAM"},
	{"Storage (MB)", "./DevDetail/Ext/Microsoft/TotalStorage"},
	{"Drive encryption", URIEncryption},
	{"Antivirus", URIAntivirus},
	{"Firewall", URIFirewall},
	{"Secure Boot", "./Vendor/MSFT/DeviceStatus/SecureBootState"},
	{"TPM version", "./Vendor/MSFT/DeviceStatus/TPM/SpecificationVersion"},
}

const (
	URIEncryption = "./Vendor/MSFT/DeviceStatus/Compliance/EncryptionCompliance"
	URIAntivirus  = "./Vendor/MSFT/DeviceStatus/Antivirus/Status"
	URIFirewall   = "./Vendor/MSFT/DeviceStatus/Firewall/Status"
)

// InventoryCommands queues a Get for every inventory URI.
func InventoryCommands(deviceID string) []store.Command {
	out := make([]store.Command, 0, len(Inventory))
	for _, it := range Inventory {
		out = append(out, store.Command{DeviceID: deviceID, Verb: "Get", LocURI: it.URI, Label: "Read " + it.Label})
	}
	return out
}

// Check is one health check shown as a green/red chip.
type Check struct {
	Name, State, Detail string // State: ok, bad, unknown
}

// Health turns raw DeviceStatus values into plain-English checks.
func Health(d store.Device) []Check {
	enc := Check{Name: "Drive encryption", State: "unknown", Detail: "Not reported yet"}
	switch d.Props[URIEncryption] {
	case "1":
		enc.State, enc.Detail = "ok", "BitLocker is protecting the drive"
	case "0":
		enc.State, enc.Detail = "bad", "Drive is not encrypted"
	}
	av := statusCheck("Antivirus", d.Props[URIAntivirus])
	fw := statusCheck("Firewall", d.Props[URIFirewall])
	return []Check{enc, av, fw}
}

func statusCheck(name, v string) Check {
	c := Check{Name: name, State: "unknown", Detail: "Not reported yet"}
	switch v {
	case "0":
		c.State, c.Detail = "ok", "On and monitoring"
	case "1":
		c.State, c.Detail = "bad", "Turned off"
	case "2":
		c.State, c.Detail = "bad", "Not monitoring everything"
	case "3":
		c.State, c.Detail = "bad", "Temporarily not monitoring"
	case "4":
		c.State, c.Detail = "unknown", "Not applicable"
	}
	return c
}

// Action is a one-click command or policy an admin can send.
type Action struct {
	Key, Label, Help string
	Danger           bool
	Commands         []store.Command // DeviceID filled in at send time
}

// Actions are the v0 catalogue. Policies are marked experimental until
// tested across Windows editions (Home editions ignore most policies).
var Actions = []Action{
	{Key: "inventory", Label: "Refresh info", Help: "Re-read hardware, Windows version and health on next check-in."},
	{Key: "require-bitlocker", Label: "Require drive encryption", Help: "Asks Windows to encrypt the system drive with BitLocker (Pro/Business editions).",
		Commands: []store.Command{{Verb: "Replace", LocURI: "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption", Format: "int", Data: "1"}}},
	{Key: "defender-on", Label: "Keep antivirus on", Help: "Stops users from turning off Microsoft Defender real-time protection.",
		Commands: []store.Command{{Verb: "Replace", LocURI: "./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring", Format: "int", Data: "1"}}},
	{Key: "auto-updates", Label: "Install updates automatically", Help: "Downloads and installs Windows updates automatically and schedules the restart.",
		Commands: []store.Command{{Verb: "Replace", LocURI: "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate", Format: "int", Data: "3"}}},
	{Key: "reboot", Label: "Restart PC", Help: "Restarts the PC at its next check-in. Unsaved work will be lost.", Danger: true,
		Commands: []store.Command{{Verb: "Exec", LocURI: "./Device/Vendor/MSFT/Reboot/RebootNow"}}},
}

// ActionByKey finds an action and returns its commands bound to a device.
func ActionByKey(key, deviceID string) (Action, []store.Command, bool) {
	for _, a := range Actions {
		if a.Key != key {
			continue
		}
		if key == "inventory" {
			return a, InventoryCommands(deviceID), true
		}
		cmds := make([]store.Command, len(a.Commands))
		for i, c := range a.Commands {
			c.DeviceID = deviceID
			c.Label = a.Label
			cmds[i] = c
		}
		return a, cmds, true
	}
	return Action{}, nil, false
}
