package main

import "testing"

func TestCanonicalVolumeGUID(t *testing.T) {
	cases := map[string]string{
		"44444444-2222-3333-4444-555555555555": "44444444-2222-3333-4444-555555555555", // ext/XFS/APFS/HFS+ UUID
		"A1B2C3D4-E5F6-7788-99AA-BBCCDDEEFF00": "A1B2C3D4-E5F6-7788-99AA-BBCCDDEEFF00", // upper-case hex is fine
		"1234-ABCD":                            "",                                     // vfat 32-bit serial: not canonical
		"deadbeefdeadbeef":                     "",                                     // NTFS $Boot serial (16 hex): not canonical
		"":                                     "",                                     // honest null
		"44444444x2222-3333-4444-555555555555": "",                                     // wrong separator
		"44444444-2222-3333-4444-5555555555":   "",                                     // too short
	}
	for in, want := range cases {
		if got := canonicalVolumeGUID(in); got != want {
			t.Errorf("canonicalVolumeGUID(%q) = %q, want %q", in, got, want)
		}
	}
}
