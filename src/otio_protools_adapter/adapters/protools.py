import struct

from copy import copy

_UNENCRYPTED_LENGTH = 20
_BITCODE = b"0010111100101011"
_ZMARK = ord(b"Z")


class Block:
    def __init__(self, zmark, block_type, block_size, content_type, offset):
        self.zmark = zmark  # "Z"
        self.block_type = block_type  # type of block
        self.block_size = block_size  # size of block
        self.content_type = content_type  # type of content
        self.offset = offset  # offset in file
        self.children: list[Block] = []  # child blocks


class AudioFile:
    def __init__(self, index, file_name=""):
        self.index = index
        self.file_name = file_name
        self.pos_absolute = 0
        self.length = 0


class Region:
    def __init__(self, index, name=""):
        self.index = index
        self.name = name
        self.start_pos = 0
        self.sample_offset = 0
        self.length = 0
        self.audio_file: AudioFile = None
        self.midi = []


class Track:
    def __init__(self, index, name, region: Region):
        self.index = index
        self.name = name
        self.region = region


# TODO @splidje: not quite working yet.
# I might have made a few mistakes reading the code I'm basing this on
def read_from_file(path):
    unxored_data = _unxor_file(path)
    version, endian_prefix = _parse_version(unxored_data)
    if version < 5 or version > 12:
        raise NotImplementedError(f"Do not support file version: {version}")

    blocks = _parse_blocks(unxored_data, endian_prefix)
    session_rate = _parse_header(blocks, unxored_data, endian_prefix)
    audio_files = _parse_audio(blocks, unxored_data, version, endian_prefix)
    regions, tracks = _parse_rest(blocks, unxored_data, audio_files, endian_prefix)
    # TODO @splidje: the actual stuff


def _unxor_file(path):
    with open(path, "rb") as file_:
        unxored_data = bytearray(file_.read())

    size = len(unxored_data)
    if size < _UNENCRYPTED_LENGTH:
        raise ValueError(f"File too short to be valid: {size} < {_UNENCRYPTED_LENGTH}")

    # Get encryption parameters from header
    xor_type, xor_value = unxored_data[_UNENCRYPTED_LENGTH - 2 : _UNENCRYPTED_LENGTH]

    # Determine xor_delta based on ProTools version
    # xor_type 0x01 = ProTools 5, 6, 7, 8, 9
    # xor_type 0x05 = ProTools 10, 11, 12
    if xor_type == 0x01:
        multiplier, sign = 53, 1
    elif xor_type == 0x05:
        multiplier, sign = 11, -1
    else:
        raise ValueError(f"Unsupported xor_type: 0x{xor_type:02x}")

    xor_delta = next(
        i * sign for i in range(256) if (i * multiplier) & 0xFF == xor_value
    )

    # Generate XOR key table
    xxor = bytes((i * xor_delta) & 0xFF for i in range(256))

    # Decrypt the rest of the file (after first 0x14 bytes)
    for i in range(_UNENCRYPTED_LENGTH, size):
        unxored_data[i] ^= xxor[i & 0xFF if xor_type == 0x01 else (i >> 12) & 0xFF]

    return bytes(unxored_data)


def _parse_version(unxored_data):
    # Check magic byte and BITCODE

    if unxored_data[0] != 3:
        raise ValueError(f"Doesn't start 0x03, instead: {unxored_data[0]}")

    if unxored_data[:256].find(_BITCODE) < 0:
        raise ValueError(f"First {256} bytes don't contain {_BITCODE}")

    # Determine endianness
    endian_prefix = ">" if unxored_data[_UNENCRYPTED_LENGTH - 3] else "<"

    # Try to parse block at 0x1f
    block = _parse_block_at(unxored_data, 31, None, 0, endian_prefix)

    if not block:
        # Fallback version detection
        version = unxored_data[64]
        if not version:
            version = unxored_data[61]
        if not version:
            version = unxored_data[58] + 2
        if version:
            return version, endian_prefix

    else:
        # Block-based version detection
        if block.content_type == 0x0003:
            # Old format
            skip = len(_parse_string(unxored_data, block.offset + 3, endian_prefix)) + 8
            version = _u_endian_read4(
                unxored_data, block.offset + 3 + skip, endian_prefix
            )
            return version, endian_prefix

        if block.content_type == 0x2067:
            # New format
            version = 2 + _u_endian_read4(
                unxored_data, block.offset + 20, endian_prefix
            )
            return version, endian_prefix

    raise ValueError("Failed to determine file version.")


def _parse_blocks(unxored_data, endian_prefix):
    blocks = []
    i = _UNENCRYPTED_LENGTH
    while i < len(unxored_data):
        block: Block = _parse_block_at(unxored_data, i, None, 0, endian_prefix)
        if block:
            blocks.append(block)
            i += block.block_size + 7
        else:
            i += 1
    return blocks


def _parse_header(blocks: list[Block], unxored_data, endian_prefix):
    for block in blocks:
        if block.content_type == 0x1028:
            return _u_endian_read4(unxored_data, block.offset + 4, endian_prefix)

    raise ValueError("session rate not found in header.")


def _parse_audio(blocks: list[Block], unxored_data: bytes, version, endian_prefix):
    for block in blocks:
        if block.content_type == 0x1004:
            break

    else:
        raise ValueError("Couldn't find audio files block")

    audio_files: list[AudioFile] = []
    audio_file_count = _u_endian_read4(unxored_data, block.offset + 2, endian_prefix)
    for child_block in block.children:
        if child_block.content_type != 0x103A:
            continue

        pos = child_block.offset + 11
        while pos < child_block.offset + child_block.block_size:
            audio_file_name = _parse_string(unxored_data, pos, endian_prefix)
            pos += len(audio_file_name) + 4
            audio_file_type = unxored_data[pos : pos + 4]
            pos += 9
            if any(s in audio_file_name for s in (".grp", "Audio Files", "Fade Files")):
                continue

            if version < 10:
                if not any(
                    s in audio_file_type for s in (b"WAVE", b"EVAW", "AIFF", "FFIA")
                ):
                    continue

            elif audio_file_type[0] and not any(
                s in audio_file_type for s in (b"WAVE", b"EVAW", b"AIFF", b"FFIA")
            ):
                continue

            elif not any(s in audio_file_name for s in (".wav", ".aif")):
                continue

            audio_files.append(AudioFile(len(audio_files), audio_file_name))

    if len(audio_files) != audio_file_count:
        raise ValueError(
            f"Number of audio files {len(audio_files)} doesn't match count {audio_file_count}"
        )

    audio_files_iter = iter(audio_files)
    for child_block in block.children:
        if child_block.content_type != 0x1003:
            continue

        for grandchild_block in child_block.children:
            if grandchild_block.content_type != 0x1001:
                continue

            audio_file = next(audio_files_iter)
            audio_file.length = _u_endian_read8(
                unxored_data, grandchild_block.offset + 8, endian_prefix
            )

    return audio_files


def _parse_rest(
    blocks: list[Block], unxored_data, audio_files: list[AudioFile], endian_prefix
):
    regions = []
    for block in blocks:
        if block.content_type not in (0x100B, 0x262A):
            continue

        for child_block in block.children:
            if child_block.content_type not in (0x1008, 0x2629):
                continue

            j = child_block.offset + 11
            region_name = _parse_string(unxored_data, j, endian_prefix)
            j += len(region_name) + 4

            regions.append(
                _parse_region_info(
                    len(regions),
                    region_name,
                    unxored_data,
                    j,
                    child_block.children[0],
                    audio_files,
                    endian_prefix,
                )
            )

    # parse tracks
    tracks: list[Track] = []
    for block in blocks:
        if block.content_type != 0x1015:
            continue

        for child_block in block.children:
            if child_block.content_type != 0x1014:
                continue

            j = child_block.offset + 2
            track_name = _parse_string(unxored_data, j, endian_prefix)
            j += len(track_name) + 5
            channel_count = _u_endian_read4(unxored_data, j, endian_prefix)
            j += 4
            for _ in range(channel_count):
                track_index = _u_endian_read2(unxored_data, j, endian_prefix)
                if track_index >= len(tracks):
                    # Add a dummy region for now
                    tracks.append(Track(track_index, track_name, Region(65535)))
                j += 2

    # TODO: midi tracks?

    # parse region->tracks
    for block in blocks:
        if block.content_type == 0x1012:
            track_iter = iter(tracks)
            for child_block in block.children:
                if child_block.content_type != 0x1011:
                    continue

                track = next(track_iter, None)
                region_name = _parse_string(
                    unxored_data, child_block.offset + 2, endian_prefix
                )
                for grandchild_block in child_block.children:
                    if grandchild_block.content_type != 0x100F:
                        continue

                    for greatgrandchild_block in grandchild_block.children:
                        if greatgrandchild_block.content_type != 0x100E:
                            continue

                        j = greatgrandchild_block.offset + 4
                        region_index = _u_endian_read4(unxored_data, j, endian_prefix)
                        if not track or region_index >= len(regions):
                            continue

                        track = copy(track)
                        track.region = copy(regions[region_index])
                        tracks.append(track)
        elif block.content_type == 0x1054:
            track_iter = iter(tracks)
            for child_block in block.children:
                if child_block.content_type != 0x1052:
                    continue

                track = next(track_iter, None)
                track_name = _parse_string(
                    unxored_data, child_block.offset + 2, endian_prefix
                )
                for grandchild_block in child_block.children:
                    if grandchild_block.content_type != 0x1050:
                        continue

                    region_is_fade = unxored_data[grandchild_block.offset + 46] == 0x01
                    if region_is_fade:
                        print("dropped fade region")
                        continue

                    for greatgrandchild_block in grandchild_block.children:
                        if greatgrandchild_block.content_type != 0x104F:
                            continue

                        j = greatgrandchild_block.offset + 4
                        region_index = _u_endian_read4(unxored_data, j, endian_prefix)
                        j += 4 + 1
                        start = _u_endian_read4(unxored_data, j, endian_prefix)
                        if not track:
                            print(f"dropped track {len(tracks)}")
                            continue

                        if region_index >= len(regions):
                            print(f"dropped region {region_index}")
                            continue

                        track = copy(track)
                        track.region = copy(regions[region_index])
                        track.region.start_pos = start
                        if track.region.index != 65535:
                            tracks.append(track)

    tracks = list(filter(lambda track: track.region.index != 65535, tracks))
    if not tracks:
        return regions, tracks

    tracks.sort(key=lambda track: track.index)

    # Renumber track entries to be gapless
    for i in range(1, len(tracks)):
        track = tracks[i]
        while track.index == tracks[i - 1].index:
            i += 1
            if i >= len(tracks):
                break

            track = tracks[i]

        if i >= len(tracks):
            break

        diffn = track.index - tracks[i - 1].index - 1
        if diffn:
            for j in range(i, len(tracks)):
                tracks[j].index -= diffn

    # Renumber track entries to be zero based
    first = tracks[0].index
    if first > 0:
        for track in tracks:
            track.index -= first

    return regions, tracks


def _parse_region_info(
    index,
    name,
    unxored_data,
    j,
    block: Block,
    audio_files: list[AudioFile],
    endian_prefix,
):
    region = Region(index, name)
    region.start_pos, region.sample_offset, region.length = _parse_three_point(
        unxored_data, j, endian_prefix
    )

    audio_file_index = _u_endian_read4(
        unxored_data, block.offset + block.block_size, endian_prefix
    )
    region.audio_file = AudioFile(audio_file_index)
    region.audio_file.pos_absolute = region.start_pos
    region.audio_file.length = region.length
    if audio_file_index < len(audio_files):
        region.audio_file.file_name = audio_files[audio_file_index].file_name
    else:
        print(audio_file_index, len(audio_files))

    return region


def _parse_three_point(unxored_data, j, endian_prefix):
    if endian_prefix == ">":
        sample_offset_bytes = (unxored_data[j + 4] & 0xF0) >> 4
        length_bytes = (unxored_data[j + 3] & 0xF0) >> 4
        start_bytes = (unxored_data[j + 2] & 0xF0) >> 4
    else:
        sample_offset_bytes = (unxored_data[j + 1] & 0xF0) >> 4
        length_bytes = (unxored_data[j + 2] & 0xF0) >> 4
        start_bytes = (unxored_data[j + 3] & 0xF0) >> 4

    if sample_offset_bytes == 5:
        sample_offset = _u_endian_read5(unxored_data, j + 5, endian_prefix)
    elif sample_offset_bytes == 4:
        sample_offset = _u_endian_read4(unxored_data, j + 5, endian_prefix)
    elif sample_offset_bytes == 3:
        sample_offset = _u_endian_read3(unxored_data, j + 5, endian_prefix)
    elif sample_offset_bytes == 2:
        sample_offset = _u_endian_read2(unxored_data, j + 5, endian_prefix)
    elif sample_offset_bytes == 1:
        sample_offset = unxored_data[j + 5]
    else:
        sample_offset = 0

    j += sample_offset_bytes

    if length_bytes == 5:
        length = _u_endian_read5(unxored_data, j + 5, endian_prefix)
    elif length_bytes == 4:
        length = _u_endian_read4(unxored_data, j + 5, endian_prefix)
    elif length_bytes == 3:
        length = _u_endian_read3(unxored_data, j + 5, endian_prefix)
    elif length_bytes == 2:
        length = _u_endian_read2(unxored_data, j + 5, endian_prefix)
    elif length_bytes == 1:
        length = unxored_data[j + 5]
    else:
        length = 0

    j += length_bytes

    if start_bytes == 5:
        start = _u_endian_read5(unxored_data, j + 5, endian_prefix)
    elif start_bytes == 4:
        start = _u_endian_read4(unxored_data, j + 5, endian_prefix)
    elif start_bytes == 3:
        start = _u_endian_read3(unxored_data, j + 5, endian_prefix)
    elif start_bytes == 2:
        start = _u_endian_read2(unxored_data, j + 5, endian_prefix)
    elif start_bytes == 1:
        start = unxored_data[j + 5]
    else:
        start = 0

    return start, sample_offset, length


def _parse_block_at(unxored_data, pos, parent, level, endian_prefix):
    if unxored_data[pos] != _ZMARK:
        return False

    max_ = (parent.block_size + parent.offset) if parent else len(unxored_data)

    block = Block(
        _ZMARK,
        _u_endian_read2(unxored_data, pos + 1, endian_prefix),
        _u_endian_read4(unxored_data, pos + 3, endian_prefix),
        _u_endian_read2(unxored_data, pos + 7, endian_prefix),
        pos + 7,
    )

    if block.block_size + block.offset > max_ or block.block_type & 0xFF00:
        return False

    child_jump = 0
    i = 1
    while i < block.block_size and (pos + i + child_jump) < max_:
        child_jump = 0
        child_block = _parse_block_at(
            unxored_data, pos + i, block, level + 1, endian_prefix
        )
        if child_block:
            block.children.append(child_block)
            child_jump = child_block.block_size + 7
        i += child_jump or 1

    return block


def _u_endian_read2(data, offset, endian_prefix):
    """Read 2-byte unsigned int with endianness"""
    return struct.unpack(f"{endian_prefix}H", data[offset : offset + 2])[0]


def _u_endian_read3(data, offset, endian_prefix):
    return _u_endian_read_nonstandard(data, offset, endian_prefix, 1, _u_endian_read4)


def _u_endian_read4(data, offset, endian_prefix):
    """Read 4-byte unsigned int with endianness"""
    return struct.unpack(f"{endian_prefix}I", data[offset : offset + 4])[0]


def _u_endian_read5(data, offset, endian_prefix):
    return _u_endian_read_nonstandard(data, offset, endian_prefix, 3, _u_endian_read8)


def _u_endian_read_nonstandard(data, offset, endian_prefix, pad_length, standard_func):
    chunk = data[offset : offset + 5]
    pad = b"\0" * pad_length
    return standard_func(
        pad + chunk if endian_prefix == ">" else chunk + pad,
        0,
        endian_prefix,
    )


def _u_endian_read8(data, offset, endian_prefix):
    """Read 8-byte unsigned int with endianness"""
    return struct.unpack(f"{endian_prefix}Q", data[offset : offset + 8])[0]


def _parse_string(data, offset, endian_prefix):
    length = _u_endian_read4(data, offset, endian_prefix)
    offset += 4
    return data[offset : offset + length].decode("latin-1")
