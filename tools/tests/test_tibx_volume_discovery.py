"""Regression tests for archives starting with an EFI boot sector."""
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tibread.tibx import TibxDiskAdapter
from tibread.mount.fuse import _open_tibx_volume
from tibread import cli


def boot_sector(filesystem):
    boot = bytearray(512)
    boot[510:] = b'\x55\xaa'
    struct.pack_into('<H', boot, 11, 512)
    boot[13] = 2
    if filesystem == 'NTFS':
        boot[3:11] = b'NTFS    '
        struct.pack_into('<Q', boot, 40, 2000000)
    else:
        boot[3:11] = b'MSDOS5.0'
        boot[82:90] = b'FAT32   '
        struct.pack_into('<I', boot, 32, 204800)
        boot[446:469] = b'ss any key to restart\r\n'
    return bytes(boot)


class VolumeDiscoveryTests(unittest.TestCase):
    def adapter(self, volume_id=None):
        with patch('tibread.tibx.disk_adapter.TibxReader'):
            adapter = TibxDiskAdapter('fake.tibx', volume_id=volume_id)
        self.addCleanup(adapter.close)
        return adapter

    def test_efi_boot_text_is_not_partition_table(self):
        adapter = self.adapter()
        adapter._reader.read_lba_range.return_value = boot_sector('FAT32')
        self.assertEqual(adapter.list_mbr_partitions(), [])

    def test_valid_mbr_still_supported(self):
        adapter = self.adapter()
        boot = bytearray(512)
        boot[510:] = b'\x55\xaa'
        boot[450] = 7
        struct.pack_into('<II', boot, 454, 2048, 100000)
        adapter._reader.read_lba_range.return_value = bytes(boot)
        self.assertEqual(adapter.list_mbr_partitions()[0]['byte_offset'], 1048576)

    def test_discovery_and_explicit_stream_read_without_disk_offset(self):
        adapter = self.adapter(volume_id=10)
        adapter._seg_index = {}
        def extent(vid, seg):
            return SimpleNamespace(key=SimpleNamespace(volume_id=vid, source_offset=0),
                                   value=SimpleNamespace(segment_id=seg), end_offset=512)
        fat, ntfs = extent(6, 1), extent(10, 2)
        adapter._extents = [fat, ntfs]
        adapter._extents_by_volume = {6: ([0], [fat]), 10: ([0], [ntfs])}
        adapter._read_segment_plaintext = lambda seg: boot_sector('FAT32' if seg == 1 else 'NTFS')
        self.assertEqual([v['filesystem'] for v in adapter.list_data_volumes()], ['FAT32', 'NTFS'])
        self.assertEqual(adapter.read(0, 512), boot_sector('NTFS'))
        self.assertEqual(adapter.partition_size, 2000000 * 512)
        self.assertEqual(adapter.read(300000, 4), b'\x00' * 4)
        adapter._reader.read_lba_range.assert_not_called()

    def test_mount_rejects_fat_before_ntfs_parser(self):
        adapter = self.adapter(volume_id=6)
        adapter.read = Mock(return_value=boot_sector('FAT32'))
        with patch('tibread.tibx.TibxDiskAdapter', return_value=adapter), patch('tibread.ntfs.NtfsVolume') as ntfs:
            with self.assertRaisesRegex(ValueError, 'not a recognized NTFS'):
                _open_tibx_volume('fake.tibx', 1, volume_id=6)
            ntfs.assert_not_called()
        self.assertIsNone(adapter._reader)

    def test_mount_opens_ntfs_stream_without_mbr_probe(self):
        adapter = self.adapter(volume_id=10)
        adapter.read = Mock(return_value=boot_sector('NTFS'))
        adapter.list_mbr_partitions = Mock(side_effect=AssertionError('unexpected MBR probe'))
        with patch('tibread.tibx.TibxDiskAdapter', return_value=adapter), patch('tibread.ntfs.NtfsVolume') as ntfs:
            volume, opened = _open_tibx_volume('fake.tibx', 1, volume_id=10)
            self.assertIs(volume, ntfs.return_value)
            self.assertIs(opened, adapter)
            ntfs.assert_called_once_with(adapter, build_index=True)

    def test_cli_forwards_volume_id(self):
        with patch('tibread.mount.fuse.fuse_mount', return_value=0) as mount:
            self.assertEqual(cli.main(['mount', 'fake.tibx', '/mnt/test', '--volume-id', '10']), 0)
            self.assertEqual(mount.call_args.kwargs['volume_id'], 10)


if __name__ == '__main__':
    unittest.main()
