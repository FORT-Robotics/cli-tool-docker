"""
note - copied partially from here: https://bitbucket.org/hriinc/epc-safety-mcu/src/master/config_blob.py

this could be combined, but the config blob structure may be phased out soon anyway.
"""

import struct
from typing import List, Tuple
from zlib import crc32

# blob contents
BLOB_SIZE = 64
# crc32, blob-num (u32), blob contents
BLOB_AND_HEADER_SIZE = 72


def build_blob(blob_num: int, payload: bytes, padding_byte: bytes = b"\x00") -> bytes:
    """build a single blob, with appended number/crc header bytes, given the raw blob data"""
    raw_data = payload + ((BLOB_SIZE - len(payload)) * padding_byte)
    blob_num_bin = struct.pack("<L", blob_num)
    blob_data = blob_num_bin + raw_data
    blob_data = struct.pack("<L", crc32(blob_data)) + blob_data
    return blob_data


def parse_blob(blob_data) -> Tuple[int, bytes]:
    """parse and validate a single blob section, extract and return the blob_num and raw data
    returns tuple(blob_num, blob_data) or raises AssertionError if crc32 invalid."""
    crc = struct.unpack_from("<L", blob_data)[0]
    blob_data = blob_data[4:]
    assert crc == crc32(blob_data)

    blob_num = struct.unpack_from("<L", blob_data)[0]
    blob_data = blob_data[4:]

    return blob_num, blob_data


def build_frc_blob_file_data(
        care_list: List[int] = [1, *(0 for i in range(63))],
        rx_keys: List[int] = [0x11223344, *(0 for i in range(63))],
        device_id: int = 2,
        tx_key: int = 0x11223344,
        comms_timeout_ms: int = 500,
        tx_rate_ms: int = 50
) -> bytes:
    assert (len(care_list) == 64), "Care-list must be 64 items"
    assert (len(rx_keys) == 64), "Rx-keys must be 64 items"
    blobs = [
        build_blob(1, struct.pack("<32H", *care_list[:32])),
        build_blob(2, struct.pack("<32H", *care_list[32:])),
        build_blob(3, struct.pack("<16L", *rx_keys[:16])),
        build_blob(4, struct.pack("<16L", *rx_keys[16:32])),
        build_blob(5, struct.pack("<16L", *rx_keys[32:48])),
        build_blob(6, struct.pack("<16L", *rx_keys[48:])),
        build_blob(7, struct.pack("<LLLL", device_id, tx_key, comms_timeout_ms, tx_rate_ms)),
    ]

    return b"".join(blobs)
