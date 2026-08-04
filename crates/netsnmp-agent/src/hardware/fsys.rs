//! Filesystem hardware abstraction.
//!
//! Counterpart of `agent/mibgroup/hardware/fsys/`. The [`FsysAccess`] trait
//! abstracts how mounted-filesystem samples and filesystem-type classification
//! are obtained, giving the HOST-RESOURCES-MIB `hrFSTable` a clean, mockable
//! source for both the disk list and the RFC 1514 `hrFSType` enumeration.
//!
//! ## Filesystem-type derivation
//!
//! The C agent calls `statvfs(2)`/`statfs(2)` and inspects the `f_fsid`/magic
//! number to classify a filesystem. `#![forbid(unsafe_code)]` blocks the libc
//! `statvfs` call (it is an `unsafe` extern), so this layer derives the
//! [`FsType`] from the already-collected filesystem-type *string* in
//! [`DiskSample::fs`] (e.g. `ext4`, `xfs`, `ntfs`, `vfat`). The mapping covers
//! the common Linux/macOS/Windows filesystems; anything unrecognised falls back
//! to [`FsType::Other`] (matching upstream behaviour for unknown magics).

use std::sync::Arc;

use crate::mibgroup::collector::{DiskSample, HostCollector};

/// RFC 1514 `hrFSType` enumeration, restricted to the values we can classify.
///
/// The numeric discriminants are the trailing sub-identifier of the
/// `hrFSTypes` OID (`1.3.6.1.2.1.25.3.9.N`), matching the RFC order so the
/// caller can build the OID by appending the discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    /// `hrFSOther` (`1.3.6.1.2.1.25.3.9.1`) — recognised but unclassified.
    Other = 1,
    /// `hrFSUnknown` (`1.3.6.1.2.1.25.3.9.2`) — type could not be determined.
    Unknown = 2,
    /// `hrFSBerkeleyFFS` (`1.3.6.1.2.1.25.3.9.3`) — UFS/FFS (BSD, macOS HFS+).
    BerkeleyFfs = 3,
    /// `hrFSSys5FS` (`1.3.6.1.2.1.25.3.9.4`) — System V filesystem.
    Sys5Fs = 4,
    /// `hrFSFat` (`1.3.6.1.2.1.25.3.9.6`) — FAT (vfat, msdos).
    Fat = 6,
    /// `hrFSHPFS` (`1.3.6.1.2.1.25.3.9.7`) — HPFS / NTFS (mapped here for NTFS).
    Hpfs = 7,
    /// `hrFSISO9660` (`1.3.6.1.2.1.25.3.9.8`) — ISO 9660 (CD-ROM).
    Iso9660 = 8,
    /// `hrFSSoftwareRoute` (`1.3.6.1.2.1.25.3.9.9`).
    SoftwareRoute = 9,
    /// `hrFSLinuxExt2` (`1.3.6.1.2.1.25.3.9.10`) — ext2/ext3/ext4.
    LinuxExt2 = 10,
    /// `hrFSXFS` (`1.3.6.1.2.1.25.3.9.14`) — SGI XFS.
    Xfs = 14,
    // Note: `hrFSBtrfs` is not in the RFC 1514 enum; btrfs maps to `Other`.
}

impl FsType {
    /// Classify a filesystem-type string (as reported by `sysinfo`, e.g.
    /// `ext4`, `xfs`, `ntfs`, `vfat`) into an [`FsType`].
    ///
    /// Matching is case-insensitive on the lower-cased string. Unknown strings
    /// map to [`FsType::Other`]; an empty string maps to [`FsType::Unknown`].
    pub fn from_fs_string(fs: &str) -> FsType {
        let s = fs.trim().to_ascii_lowercase();
        if s.is_empty() {
            return FsType::Unknown;
        }
        // ext2/ext3/ext4 -> LinuxExt2.
        if s == "ext2" || s == "ext3" || s == "ext4" {
            return FsType::LinuxExt2;
        }
        if s == "xfs" {
            return FsType::Xfs;
        }
        if s == "ntfs" || s == "ntfs-3g" {
            return FsType::Hpfs;
        }
        if s == "vfat" || s == "fat" || s == "fat32" || s == "msdos" || s == "fat16" {
            return FsType::Fat;
        }
        if s == "iso9660" {
            return FsType::Iso9660;
        }
        if s == "ufs" || s == "ffs" || s == "hfs" || s == "hfs+" || s == "apfs" || s == "zfs" {
            // UFS/FFS is the closest RFC match for BSD-origin or Apple
            // filesystems; ZFS has no RFC enum either, so use BerkeleyFFS as
            // the least-wrong "known filesystem" classification rather than
            // Other (which upstream reserves for truly unrecognised types).
            return FsType::BerkeleyFfs;
        }
        if s == "sysv" || s == "s5" {
            return FsType::Sys5Fs;
        }
        FsType::Other
    }

    /// The trailing sub-identifier to append to the `hrFSTypes` OID prefix
    /// (`1.3.6.1.2.1.25.3.9`) for this filesystem type.
    pub fn as_oid_suffix(&self) -> u32 {
        *self as u32
    }
}

/// Read-side access to mounted-filesystem data.
pub trait FsysAccess: Send + Sync {
    /// Mounted filesystems, in a stable order.
    fn filesystems(&self) -> Vec<DiskSample>;

    /// Classify the filesystem mounted at `mount` (matched by mount point)
    /// into an [`FsType`]. Returns [`FsType::Unknown`] when the mount is not
    /// found.
    fn fs_type(&self, mount: &str) -> FsType;
}

/// Default [`FsysAccess`] backed by the shared [`HostCollector`].
pub struct SysFsysAccess {
    /// The shared collector; reads go through its throttled snapshot.
    pub(super) inner: Arc<HostCollector>,
}

impl SysFsysAccess {
    /// Create a new filesystem access layer over `collector`.
    pub fn new(collector: Arc<HostCollector>) -> Self {
        SysFsysAccess { inner: collector }
    }
}

impl FsysAccess for SysFsysAccess {
    fn filesystems(&self) -> Vec<DiskSample> {
        self.inner.snapshot().disks.clone()
    }

    fn fs_type(&self, mount: &str) -> FsType {
        let snap = self.inner.snapshot();
        for d in snap.disks.iter() {
            if d.mount == mount {
                return FsType::from_fs_string(&d.fs);
            }
        }
        FsType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_maps_to_linux_ext2() {
        assert_eq!(FsType::from_fs_string("ext4"), FsType::LinuxExt2);
        assert_eq!(FsType::from_fs_string("ext3"), FsType::LinuxExt2);
        assert_eq!(FsType::from_fs_string("ext2"), FsType::LinuxExt2);
        assert_eq!(
            FsType::from_fs_string("EXT4"),
            FsType::LinuxExt2,
            "case-insensitive"
        );
    }

    #[test]
    fn xfs_maps_to_xfs() {
        assert_eq!(FsType::from_fs_string("xfs"), FsType::Xfs);
    }

    #[test]
    fn ntfs_maps_to_hpfs() {
        assert_eq!(FsType::from_fs_string("ntfs"), FsType::Hpfs);
        assert_eq!(FsType::from_fs_string("ntfs-3g"), FsType::Hpfs);
    }

    #[test]
    fn vfat_maps_to_fat() {
        assert_eq!(FsType::from_fs_string("vfat"), FsType::Fat);
        assert_eq!(FsType::from_fs_string("fat32"), FsType::Fat);
        assert_eq!(FsType::from_fs_string("msdos"), FsType::Fat);
    }

    #[test]
    fn btrfs_maps_to_other() {
        assert_eq!(FsType::from_fs_string("btrfs"), FsType::Other);
    }

    #[test]
    fn empty_maps_to_unknown() {
        assert_eq!(FsType::from_fs_string(""), FsType::Unknown);
        assert_eq!(FsType::from_fs_string("   "), FsType::Unknown);
    }

    #[test]
    fn ufs_hfs_apfs_zfs_map_to_berkeley_ffs() {
        assert_eq!(FsType::from_fs_string("ufs"), FsType::BerkeleyFfs);
        assert_eq!(FsType::from_fs_string("apfs"), FsType::BerkeleyFfs);
        assert_eq!(FsType::from_fs_string("zfs"), FsType::BerkeleyFfs);
    }

    #[test]
    fn oid_suffix_matches_discriminant() {
        assert_eq!(FsType::LinuxExt2.as_oid_suffix(), 10);
        assert_eq!(FsType::Xfs.as_oid_suffix(), 14);
        assert_eq!(FsType::Other.as_oid_suffix(), 1);
    }
}
