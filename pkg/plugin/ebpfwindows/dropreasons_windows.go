package ebpfwindows

import (
	"fmt"
)

// DropMin numbers less than this are non-drop reason codes
var DropMin uint8 = 130

// DropInvalid is the Invalid packet reason.
var DropInvalid uint8 = 2

// Packet Monitor drop reason
var DropPacketMonitor uint8 = 220

// These values are shared with bpf/lib/common.h and api/v1/flow/flow.proto.
var dropErrors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	3:   "Plain Text",
	4:   "Interface Decrypted",
	5:   "LB: No backend slot entry found",
	6:   "LB: No backend entry found",
	7:   "LB: Reverse entry update failed",
	8:   "LB: Reverse entry stale",
	9:   "Fragmented packet",
	10:  "Fragmented packet entry update failed",
	11:  "Missed tail call to custom program",
	167: "SNAT map entry not found",
	181: "DropReason_PolicyDeny",
	220: "PacketMonitor dropped packet",
}

var dropExtendedErrors = map[int16]string{
	903: "Protocol unreachable",
	904: "Port unreachable",
}

// Keep in sync with __id_for_file in bpf/lib/source_info.h.
var files = map[uint8]string{

	// source files from bpf/
	1: "bpf_host.c",
	2: "bpf_lxc.c",
	3: "bpf_overlay.c",
	4: "bpf_xdp.c",
	5: "bpf_sock.c",
	6: "bpf_network.c",

	// header files from bpf/lib/
	101: "arp.h",
	102: "drop.h",
	103: "srv6.h",
	104: "icmp6.h",
	105: "nodeport.h",
	106: "lb.h",
	107: "mcast.h",
	108: "ipv4.h",
	109: "conntrack.h",
	110: "l3.h",
	111: "trace.h",
	112: "encap.h",
	113: "encrypt.h",
}

// BPFFileName returns the file name for the given BPF file id.
func BPFFileName(id uint8) string {
	if name, ok := files[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", id)
}

func extendedReason(extError int16) string {
	if extError == int16(0) {
		return ""
	}

	return fmt.Sprintf("%d", extError)
}

func DropReasonExt(reason uint8, extError int16) string {
	var ext string

	if err, ok := dropErrors[reason]; ok {
		if ext := extendedReason(int16(extError)); ext == "" {
			return err
		}
		return err + ", " + ext
	}

	return fmt.Sprintf("%d, %d", reason, extError)
}

// DropReason prints the drop reason in a human readable string
func DropReason(reason uint8) string {
	return DropReasonExt(reason, int16(0))
}
