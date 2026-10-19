// Origin-record helpers shared by the identify and materialise verbs: the
// evidence-asset identity keys of the frozen gomount↔gopinfo contract.
package main

// canonicalVolumeGUID returns uuid when it is a canonical 128-bit UUID
// (8-4-4-4-12 hex — what ext/XFS/APFS/HFS+ carry), else "". It is the
// volume_guid rule: a filesystem's UUID is a volume GUID only when it is a
// real 128-bit identifier. vfat's 32-bit "xxxx-xxxx" serial and the NTFS
// $Boot serial are NOT, so they return "" (NTFS identity rides
// disk_id/part_guid/part_offset instead; the Windows \\?\Volume{GUID} is
// derived downstream).
func canonicalVolumeGUID(uuid string) string {
	// 8-4-4-4-12 with hyphens at the fixed positions, hex everywhere else.
	if len(uuid) != 36 {
		return ""
	}
	for i, c := range uuid {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return ""
			}
		default:
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return ""
			}
		}
	}
	return uuid
}
