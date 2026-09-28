#!/usr/bin/env bash
# Regenerates the committed filesystem fixtures with REAL formatting tools
# (e2fsprogs, xfsprogs, dosfstools, mtools) — the backends are clean-room,
# so the fixtures must come from the canonical implementations, never from
# the code under test. Residue is crafted with debugfs/mdel. Images are
# committed gzipped; tests gunzip to a temp file.
#
#   cd gomount/fsx/testdata && ./gen.sh
#
# The Apple fixtures are not generated here — no Linux host can format them.
# hfsplus-transmission.img.gz and apfs-container.img.gz are the raw disks
# inside Homebrew's transmission-2.61.dmg and container-apfs.dmg cask test
# fixtures (github.com/Homebrew/brew, BSD-2-Clause — THIRD_PARTY_NOTICES.md),
# written by Apple's diskutil/hdiutil: the UDIF container unpacked and its
# zlib chunks reassembled (first by a 30-line script; gomount's own DMG
# reader, image/dmg.go, now reproduces them byte for byte from the DMGs in
# image/testdata/ — image/dmg_test.go checks it). HFS+ fixtures for the
# shapes those do not cover come from fsx/hfsplus/hfstest at test time.
set -euo pipefail
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tree="$work/tree"
mkdir -p "$tree"/{etc,var/log,home/alice,bigdir,lost+found}
printf 'web01\n' > "$tree/etc/hostname"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\n' > "$tree/etc/os-release"
printf 'Jan 10 22:14:02 web01 systemd[1]: Started daily apt activities.\nJan 10 22:15:00 web01 CRON[311]: (alice) CMD (/usr/bin/backup)\n' > "$tree/var/log/syslog"
printf 'ls -la\nsystemctl status nginx\n' > "$tree/home/alice/.bash_history"
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256))*400)" > "$tree/big.bin"
for i in $(seq -w 1 120); do printf 'entry %s\n' "$i" > "$tree/bigdir/file-$i.txt"; done
ln -s ../usr/share/zoneinfo/Europe/Berlin "$tree/etc/localtime"
ln -s "$(python3 -c 'print("t"*80)')" "$tree/etc/longlink"
printf 'delete me\n'  > "$tree/todelete.txt"
printf 'sweep orphan content\n' > "$tree/orphan-sweep.txt"
printf 'chain orphan content\n' > "$tree/orphan-chain.txt"
printf 'recovered by fsck\n' > "$tree/lost+found/#12"

# ---- ext4: 256-byte inodes (crtime), extents, htree, metadata_csum ----------
rm -f ext4.img
truncate -s 8m ext4.img
mke2fs -q -F -t ext4 -b 1024 -I 256 -L rootfs \
  -U 21111111-2222-3333-4444-555555555555 -d "$tree" ext4.img
# pinned MACB + crtime on /etc/hostname (asserted exactly by the tests)
debugfs -w -R "sif /etc/hostname mtime 20260110221402" ext4.img >/dev/null 2>&1
debugfs -w -R "sif /etc/hostname atime 20260111090000" ext4.img >/dev/null 2>&1
debugfs -w -R "sif /etc/hostname ctime 20260110221402" ext4.img >/dev/null 2>&1
debugfs -w -R "sif /etc/hostname crtime 20260101000000" ext4.img >/dev/null 2>&1
debugfs -w -R "sif /home/alice/.bash_history uid 1000" ext4.img >/dev/null 2>&1
debugfs -w -R "sif /home/alice/.bash_history gid 1000" ext4.img >/dev/null 2>&1
# residue: a deleted dirent, a sweep orphan, a chain orphan
osweep=$(debugfs -R "stat /orphan-sweep.txt" ext4.img 2>/dev/null | sed -n 's/^Inode: \([0-9]*\).*/\1/p')
ochain=$(debugfs -R "stat /orphan-chain.txt" ext4.img 2>/dev/null | sed -n 's/^Inode: \([0-9]*\).*/\1/p')
debugfs -w -R "rm /todelete.txt" ext4.img >/dev/null 2>&1
debugfs -w -R "unlink /orphan-sweep.txt" ext4.img >/dev/null 2>&1
debugfs -w -R "unlink /orphan-chain.txt" ext4.img >/dev/null 2>&1
debugfs -w -R "sif <$ochain> links_count 0" ext4.img >/dev/null 2>&1
debugfs -w -R "ssv last_orphan $ochain" ext4.img >/dev/null 2>&1
echo "ext4: sweep-orphan inode=$osweep chain-orphan inode=$ochain"
gzip -9 -f ext4.img

# ---- ext2: 128-byte inodes, direct/indirect maps ----------------------------
rm -f ext2.img
truncate -s 2m ext2.img
mkdir -p "$work/tree2"
printf 'classic filesystem\n' > "$work/tree2/README"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i*7)%256 for i in range(300*1024)))" > "$work/tree2/indirect.bin"
ln -s README "$work/tree2/link"
mke2fs -q -F -t ext2 -b 1024 -I 128 -L classic \
  -U 22222222-2222-3333-4444-555555555555 -d "$work/tree2" ext2.img
gzip -9 -f ext2.img

# ---- xfs: v5, shortform + block/leaf dirs, symlink --------------------------
rm -f xfs.img
truncate -s 310m xfs.img
proto="$work/proto"
{
  printf '/\n0 0\nd--755 0 0\n'
  printf 'etc d--755 0 0\n'
  printf 'hostname ---644 0 0 %s\n' "$tree/etc/hostname"
  printf 'os-release ---644 0 0 %s\n' "$tree/etc/os-release"
  printf 'localtime l--777 0 0 ../usr/share/zoneinfo/Europe/Berlin\n'
  printf '$\n'
  printf 'var d--755 0 0\n'
  printf 'log d--755 0 0\n'
  printf 'syslog ---640 0 4 %s\n' "$tree/var/log/syslog"
  printf '$\n$\n'
  printf 'big.bin ---644 1000 1000 %s\n' "$tree/big.bin"
  printf 'bigdir d--755 0 0\n'
  for i in $(seq -w 1 300); do printf 'leaf-%s.txt ---644 0 0 %s\n' "$i" "$tree/etc/hostname"; done
  printf '$\n$\n'
} > "$proto"
# nrext64=0 keeps the classic inode extent counters; bigtime/ftype/crc
# stay at the v5 defaults the backend implements.
mkfs.xfs -q -f -L xfsroot -m uuid=33333333-2222-3333-4444-555555555555 \
  -i nrext64=0 -p "$proto" xfs.img
gzip -9 -f xfs.img

# ---- vfat: FAT12 (small) and FAT32, LFN names, one deleted entry ------------
rm -f fat12.img fat32.img
truncate -s 4m fat12.img
mkfs.vfat -F 12 -n EFIBOOT -i CAFE1234 fat12.img >/dev/null
mcopy -i fat12.img "$tree/etc/hostname" ::HOSTNAME.TXT
mcopy -i fat12.img "$tree/var/log/syslog" "::A Long File Name.log"
mmd   -i fat12.img ::EFI
mcopy -i fat12.img "$tree/etc/os-release" "::EFI/grub configuration.cfg"
# deletions LAST: a later mcopy would reuse the freed slots
mcopy -i fat12.img "$tree/etc/os-release" ::DELETEME.TXT
mcopy -i fat12.img "$tree/var/log/syslog" "::deleted long name.txt"
mdel  -i fat12.img ::DELETEME.TXT
mdel  -i fat12.img "::deleted long name.txt"
gzip -9 -f fat12.img

truncate -s 36m fat32.img
mkfs.vfat -F 32 -n BIGDATA -i DEAD0001 fat32.img >/dev/null
mcopy -i fat32.img "$tree/big.bin" ::BIG.BIN
mcopy -i fat32.img "$tree/etc/hostname" "::nested name with spaces.txt"
gzip -9 -f fat32.img

# ---- lvm: MBR + two PVs, a linear lv holding a REAL ext4, a striped lv ------
rm -f lvm.img
truncate -s 6m "$work/lvroot.img"
mkdir -p "$work/lvtree"
printf 'hello from inside the lv\n' > "$work/lvtree/inside-lv.txt"
mke2fs -q -F -t ext4 -b 1024 -I 256 -L lvroot \
  -U 44444444-2222-3333-4444-555555555555 -d "$work/lvtree" "$work/lvroot.img"
go run gen-lvm.go lvm.img "$work/lvroot.img"
gzip -9 -f lvm.img

ls -la *.img.gz
