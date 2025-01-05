from abc import ABC, abstractmethod
import json
import math
import os
from typing import Any, Awaitable, Callable, Optional, Tuple, TypeVar, Union
from logging import Logger, getLevelNamesMapping, getLogger, basicConfig, WARN
from hashlib import sha1
from urllib.parse import urlencode, parse_qs
import urllib.request
import argparse
from dataclasses import dataclass
import asyncio
import random
import string
import binascii

log_level = getLevelNamesMapping()[os.environ.get("LOGLEVEL", "DEBUG")] or WARN

basicConfig(
    level=log_level,
    format="%(name)s[%(filename)s:%(lineno)s %(funcName)s()]: %(message)s",
)
global_logger = getLogger(__name__)


ValueType = Union[int, bytes, list["ValueType"], dict[str, "ValueType"]]


@dataclass
class Peer(object):
    ip: str
    port: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Peer":
        ip = ".".join([str(x) for x in data[:4]])
        port = parse_integer(data[4:6])
        return cls(ip, port)


@dataclass
class TrackerPeersResponse:
    length: bytes
    protocol: bytes
    reserved: bytes
    sha1_hash: bytes
    peer_id: bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "TrackerPeersResponse":
        if len(data) != 68:
            raise ValueError(f"Invalid tracker peers response length: {data} ({len(data)})")

        return cls(
            length=data[0:1],
            protocol=data[1:20],
            reserved=data[20:28],
            sha1_hash=data[28:48],
            peer_id=data[48:],
        )


@dataclass
class PeerMessage(ABC):
    # message_length: int
    # message_id: int
    # message_payload: bytes

    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError("encode method not implemented")


@dataclass
class Have(PeerMessage):
    piece_index: int
    id = 4

    @classmethod
    def from_bytes(cls, data: bytes) -> "Have":
        length = parse_integer(data[0:4])
        if length != 5:
            raise ValueError(f"Invalid Have message length: {length}")

        id = parse_integer(data[4:5])
        if id != cls.id:
            raise ValueError(f"Invalid Have message id: {id}")

        return cls(
            piece_index=parse_integer(data[5:]),
        )

    def encode(self) -> bytes:
        payload = encode_integer(self.id) + encode_integer(self.piece_index)
        return encode_integer(len(payload)) + payload


@dataclass
class Port(PeerMessage):
    port: int
    id = 14

    @classmethod
    def from_bytes(cls, data: bytes) -> "Port":
        length = parse_integer(data[0:4])
        if length != 1 and length != 5:
            raise ValueError(f"Invalid Port message length: {length}")

        id = int.from_bytes(data[4:5])
        if id != cls.id:
            raise ValueError(f"Invalid Have message id: {id}")

        port = 0
        if length == 5:
            port = parse_integer(data[5:])

        return cls(
            port=port,
        )

    def encode(self) -> bytes:
        if self.port > 0:
            payload = encode_integer(self.id) + encode_integer(self.port)
            return encode_integer(len(payload)) + payload

        payload = encode_integer(14)
        return encode_integer(len(payload)) + payload


@dataclass
class Interested(PeerMessage):
    id = 2

    @classmethod
    def from_bytes(cls, data: bytes) -> "Interested":
        length = parse_integer(data[0:4])
        if length != 1:
            raise ValueError(f"Invalid Interested message length: {length}")

        id = parse_integer(data[4:5])
        if id != cls.id:
            raise ValueError(f"Invalid Interested message id: {id}")

        return cls()

    def encode(self) -> bytes:
        payload = encode_id(self.id)
        return encode_integer(len(payload)) + payload


@dataclass
class Unchoke(PeerMessage):
    id = 1

    @classmethod
    def from_bytes(cls, data: bytes) -> "Unchoke":
        length = parse_integer(data[0:4])
        if length != 1:
            raise ValueError(f"Invalid Unchoke message length: {length}")

        id = parse_integer(data[4:5])
        if id != cls.id:
            raise ValueError(f"Invalid Unchoke message id: {id}")

        return cls()

    def encode(self) -> bytes:
        payload = encode_id(self.id)
        return encode_integer(len(payload)) + payload


@dataclass
class Request(PeerMessage):
    index: int
    begin: int
    length: int

    id = 6

    @classmethod
    def from_bytes(cls, data: bytes) -> "Request":
        length = parse_integer(data[0:4])
        if length != 13:
            raise ValueError(f"Invalid Request message length: {length}")

        id = parse_integer(data[4:5])
        if id != cls.id:
            raise ValueError(f"Invalid Request message id: {id}")

        return cls(
            index=parse_integer(data[5:9]),
            begin=parse_integer(data[9:13]),
            length=parse_integer(data[13:]),
        )

    def encode(self) -> bytes:
        payload = encode_id(self.id) \
            + encode_integer(self.index) \
            + encode_integer(self.begin) \
            + encode_integer(self.length)

        return encode_integer(len(payload)) + payload


@dataclass
class Piece(PeerMessage):
    index: int
    begin: int
    block: bytes

    id = 7

    @classmethod
    def from_bytes(cls, data: bytes) -> "Piece":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5]) # 1 byte
        index = parse_integer(data[5:9]) # 4 bytes
        begin = parse_integer(data[9:13]) # 4 bytes
        block = data[13:]

        if id != cls.id:
            raise ValueError(f"Invalid Piece message id: {id}")

        return cls(
            index=index,
            begin=begin,
            block=block,
        )

    def encode(self) -> bytes:
        payload = encode_id(self.id) \
            + encode_integer(self.index) \
            + encode_integer(self.begin) \
            + self.block

        return encode_integer(len(payload)) + payload

    def __str__(self) -> str:
        return f"Piece(" + \
            f"index={self.index}, " + \
            f"begin={self.begin}, " + \
            f"block=<truncated>, " + \
            f"message_id={self.id}, " + \
            f"block_length={len(self.block)}" + \
       ")"


@dataclass
class Bitfield(PeerMessage):
    bitfield: bytes

    id = 5

    @classmethod
    def from_bytes(cls, data: bytes) -> "Bitfield":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5])
        bitfield = data[5:]

        if length != len(bitfield) + 1:
            raise ValueError(f"Invalid Bitfield message length: {length}")

        if id != cls.id:
            raise ValueError(f"Invalid Bitfield message id: {id}") 

        return cls(
            bitfield=bitfield,
        )

    def encode(self) -> bytes:
        payload = encode_id(self.id) + self.bitfield
        return encode_integer(len(payload)) + payload


T = TypeVar("T")
@dataclass
class Extension(PeerMessage):
    extension_id: int
    metadata: dict[str, Any]
    contents: Optional[ValueType]

    id: int = 20

    def m(self) -> dict[str, int]:
        extensions: dict[str, int] = {}

        m = self.metadata.get("m")
        if m is not None:
            if type(m) is not dict:
                raise ValueError("unexpected m structure")

            for k, v in m.items():
                if type(k) != str:
                    raise ValueError(f"Invalid extension handshake: {k}")

                if type(v) != int:
                    raise ValueError(f"Invalid extension handshake: {v}")

                extensions[k] = v

        return extensions

    def get(self, key: str, t: T) -> Optional[T]:
        value = self.metadata.get(key)
        if value is None:
            return t

        if type(value) != t:
            raise ValueError(f"Invalid extension handshake: {value}")

        return value

    @classmethod
    def from_bytes(cls, data: bytes) -> "Extension":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5])
        payload = data[5:]
        extended_id = parse_integer(payload[0:1])
        opt_handshake = decode(payload[1:])

        if length != len(payload) + 1:
            raise ValueError(f"Invalid ExtensionHandshake message length: {length}")

        if id != cls.id:
            raise ValueError(f"Invalid ExtensionHandshake message id: {id}")

        if opt_handshake is None:
            raise ValueError(f"Invalid extension handshake: {payload}")

        metadata, encoded_contents = opt_handshake

        contents = None
        decoded_contents = decode(encoded_contents)
        if decoded_contents is not None:
            contents, _ = decoded_contents

        if type(metadata) != dict:
            raise ValueError(f"Invalid extension handshake: {metadata}")

        return cls(
            extension_id=extended_id,
            metadata=metadata,
            contents=contents,
        )

    def encode(self) -> bytes:
        message_id = encode_id(self.id)
        extension_id = encode_id(self.extension_id)
        handshake = encode(self.metadata)
        payload = message_id + extension_id + handshake
        return encode_integer(len(payload)) + payload


def decode_peer_message(data: bytes) -> Optional[PeerMessage]:
    id = parse_integer(data[4:5])

    match id:
        case Unchoke.id:
            return Unchoke.from_bytes(data)
        case Interested.id:
            return Interested.from_bytes(data)
        case Have.id:
            return Have.from_bytes(data)
        case Bitfield.id:
            return Bitfield.from_bytes(data)
        case Piece.id:
            return Piece.from_bytes(data)
        case Port.id:
            return Port.from_bytes(data)
        case Extension.id:
            return Extension.from_bytes(data)
        case _:
            global_logger.warning(f"Ignoring message with id %{id}")
            return None


def decode_int(value: bytes) -> Optional[Tuple[int, bytes]]:
    if len(value) < 2:
        return None

    header, body = value[0], value[1:]
    if header != ord("i"):
        return None

    numeric = bytes()
    while len(body) > 0 and body[0] != ord("e"):
        numeric = b"".join([numeric, body[0:1]])
        body = body[1:]

    if len(body) == 0:
        global_logger.error(f"no end of integer found: '{numeric}'")
        return None

    end, the_rest = body[0], body[1:]
    if end != ord("e"):
        global_logger.error(f"invalid end of integer: '{end}'")
        return None

    try:
        return int(numeric), the_rest
    except ValueError:
        global_logger.error(f"invalid integer value: '{numeric}'")
        return None


def decode_string(value: bytes) -> Optional[Tuple[bytes, bytes]]:
    str_len = bytes()

    while len(value) > 0 and value[0] != ord(":"):
        str_len = b"".join([str_len, value[0:1]])
        value = value[1:]

        if str_len.isdigit() is False:
            return None

    if len(value) == 0 or value[0] != ord(":"):
        global_logger.error(f"no colon found: '{value}'")
        return None

    try:
        length = int(str_len.decode())
    except ValueError:
        global_logger.error(f"invalid string length: '{str_len}'")
        return None

    if length + 1 > len(value):
        global_logger.error(f"string length too long: '{length + 1} {type(length)}' >  '{len(value)}'")
        return None

    try:
        string = value[1:length + 1]
        the_rest = value[length + 1:]
        return string, the_rest 
    except UnicodeDecodeError:
        global_logger.error(f"invalid string encoding: '{value[1:length + 1]}'")
        return None


def decode_list(value: bytes) -> Optional[Tuple[list[ValueType], bytes]]:
    if len(value) < 2:
        return None

    header, body = value[0], value[1:]

    if header != ord("l"):
        return None

    elements = []

    while len(body) > 0 and not body[0] == ord("e"):
        decoded_value = decode(body)
        if decoded_value is None:
            global_logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")

        element, body = decoded_value
        if element is None:
            global_logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")

        elements.append(element)

    if len(body) == 0:
        global_logger.error(f"invalid end of list: '{body}'")
        return None

    if body[0] != ord("e"):
        global_logger.error(f"invalid end of list: '{body[0]}'")
        return None

    return elements, body[1:]


def decode_dict(value: bytes) -> Optional[Tuple[dict[ValueType, ValueType], bytes]]:
    if len(value) < 2:
        return None

    header, body = value[0], value[1:]
    if header != ord("d"):
        return None

    elements = {}

    while len(body) > 0 and not body[0] == ord("e"):
        key_value = decode(body)
        if key_value is None:
            global_logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")
        k, body = key_value

        if type(k) != bytes:
            global_logger.error(f"Invalid key type: '{k}'")
            raise ValueError("Invalid key type")

        k = k.decode()

        value_value = decode(body)
        if value_value is None:
            global_logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")
        v, body = value_value

        elements[k] = v

    if len(body) == 0:
        global_logger.error(f"invalid end of dict: '{body}'")
        return None

    if body[0] != ord("e"):
        global_logger.error(f"invalid end of dict: '{body[0]}'")
        return None

    return elements, body[1:]


def decode(value: bytes) -> Optional[Tuple[ValueType, bytes]]:
    decorder = [decode_int, decode_string, decode_list, decode_dict]

    if len(value) == 0:
        return None

    for decoder in decorder:
        decoded_value = decoder(value[:])
        if decoded_value is None:
            continue

        return decoded_value

    raise ValueError(f"failed to decode value: '{value}'")


def encode(data: Any) -> bytes:
    match data:
        case int():
            return f"i{data}e".encode()
        case bytes():
            return f"{len(data)}:".encode() + data
        case str():
            return f"{len(data)}:{data}".encode()
        case list():
            return b"l" + b"".join([ encode(y) for y in data ]) + b"e"
        case dict():
            return b"d" + b"".join([encode(k) + encode(y) for k, y in data.items()])  + b"e"
        case _:
            raise NotImplementedError(f"Unsupported type: {type(data)}")


def decode_torrent_file(file: str) -> dict[str, ValueType]:
    if not os.path.exists(file):
        raise FileNotFoundError(f"File not found: {file}")

    with open(file, "rb") as f:
        bencoded_value = f.read()

    data = decode(bencoded_value)

    if data is None:
        raise ValueError("Unable to parse content")

    data, _ = data

    if type(data) != dict:
        raise ValueError(f"Invalid data structured. Expected dict: '{data}', ({type(data)})")

    if "announce" not in data.keys():
        raise ValueError(f"missing announce information: {data}")

    if "info" not in data.keys():
        raise ValueError(f"missing info information: {data}")

    if type(data["info"]) != dict:
        raise ValueError(f"missing info information: {data}")

    if "length" not in data["info"].keys():
        raise ValueError(f"missing length information: {data}")

    if "pieces" not in data["info"].keys():
        raise ValueError(f"missing pieces information: {data}")

    return data


def get_torrent_url(torrent_data: dict[str, ValueType]) -> str:
    torrent_url = torrent_data["announce"]

    if not isinstance(torrent_url, bytes):
        raise Exception(f"invalid type: '{type(torrent_url)}'")

    return torrent_url.decode()


def generate_info_hash(torrent_data: dict[str, ValueType]) -> bytes:
    if "info_hash" in torrent_data.keys():
        if isinstance(torrent_data["info_hash"], bytes):
            return torrent_data["info_hash"]
        raise ValueError(f"invalid type for info_hash: '{type(torrent_data['info_hash'])}'")

    if "info" not in torrent_data.keys():
        raise ValueError("missing info key")

    info = torrent_data["info"]
    info_hash = sha1(encode(info))
    return info_hash.digest()


def parse_integer(data: bytes) -> int:
    return int.from_bytes(data, "big")


def encode_integer(data: int) -> bytes:
    return data.to_bytes(4, "big")


def encode_id(id: int) -> bytes:
    return id.to_bytes(1, "big")


@dataclass
class ChunkMeta(object):
    piece_index: int
    index: int
    begin: int
    length: int


@dataclass
class PieceMeta(object):
    index: int
    hash: bytes
    length: int
    pipeline_size: int

    def pipeline_chunks(self) -> list[ChunkMeta]:
        amount_of_pieces = math.ceil(self.length / self.pipeline_size)
        last_piece_size = self.length % self.pipeline_size or self.pipeline_size

        global_logger.debug(f"Pipeline size: {self.pipeline_size}, amount of pieces: {amount_of_pieces}, last piece size: {last_piece_size}")

        return [
            ChunkMeta(
                piece_index=self.index,
                index=x,
                begin=x * self.pipeline_size,
                length=self.pipeline_size if x != amount_of_pieces - 1 or last_piece_size == 0 else last_piece_size,
            )
            for x
            in range(amount_of_pieces)
        ]


class Tracker(object):
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _conn: tuple[str, int]
    _logger: Logger

    def __init__(self, conn: tuple[str, int]) -> None:
        self._logger = getLogger(f"peer@{conn[0]}:{conn[1]}")
        self._conn = conn

    async def _connect(self, conn: tuple[str, int]) -> None:
        self._reader, self._writer = await asyncio.open_connection(conn[0], conn[1])

    async def handshake(
            self,
            info_hash: bytes,
            peer_id: bytes,
            reserved_bits: bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00",
    ) -> TrackerPeersResponse:
        # TODO: could this be a peer message instead?
        # Unsure if it can because the message begins with with the number
        # 19, which is the length of the protocol string. The length of the
        # protocol is 68 bytes, which doesn't make sense for the prefix.
        # 19 bytes returns the protocol string 'BitTorrent protocol' which
        # is then followed by the reserved bytes, info hash, and peer id.
        # Would we read the payload which is the protocol string and then
        # read another 49 bytes to get the rest of the message?

        h = b"\x13BitTorrent protocol" \
            + reserved_bits \
            + info_hash \
            + peer_id

        self._writer.write(h)
        await self._writer.drain()

        return TrackerPeersResponse.from_bytes(await self._reader.read(68))

    async def listen_for_messages(self) -> Optional[PeerMessage]:
        try:
            message_length_bytes = await self._reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return None

        if len(message_length_bytes) == 0:
            return None

        # TODO: sanity check message length
        message_length = parse_integer(message_length_bytes)
        if message_length == 0:
            # keep alive, ignore
            self._logger.debug("Keep alive message")
            return None

        payload = await self._reader.readexactly(message_length)
        assert len(payload) == message_length, f"Invalid message length: {len(payload)} != {message_length}"
        return decode_peer_message(message_length_bytes + payload)

    async def send_message(self, message: PeerMessage) -> None:
        self._writer.write(message.encode())
        await self._writer.drain()

    async def start_piece_downloads(self, piece_index: int, piece_begin: int, piece_length: int) -> Optional[int]:
        await self.send_message(Request(
            piece_index,
            piece_begin,
            piece_length,
        ))

        return piece_index

    async def __aenter__(self):
        await self._connect(self._conn)
        return self

    async def __aexit__(self, *_) -> None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            self._logger.exception("Failed to close connection")


def generate_peer_id() -> bytes:
    prefix = "-MW0001-"
    random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return (prefix + random_part).encode("utf-8")


async def tracker_handshake(
    torrent_data: dict[str, ValueType],
    tracker: Tracker,
    reserved_bits: bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00",
) -> TrackerPeersResponse:
    info_hash = generate_info_hash(torrent_data)
    peer_id = generate_peer_id()
    return await tracker.handshake(info_hash, peer_id, reserved_bits)


def get_length(torrent_data: dict[str, ValueType]) -> int:
    if "info" not in torrent_data.keys():
        raise ValueError(f"missing info key: {torrent_data}")

    info = torrent_data["info"]
    if not isinstance(info, dict):
        raise ValueError(f"invalid type: '{type(info)}'")

    length = info["length"]
    if not isinstance(length, int):
        raise ValueError(f"invalid type: '{length}'")

    return length


def get_pieces(torrent_data: dict[str, ValueType]) -> bytes:
    if "info" not in torrent_data.keys():
        raise ValueError(f"missing info key: {torrent_data}")

    info = torrent_data["info"]
    if not isinstance(info, dict):
        raise ValueError(f"invalid type: '{type(info)}'")

    if "pieces" not in info.keys():
        raise ValueError(f"missing pieces key: {info}")

    pieces = info["pieces"]
    if not isinstance(pieces, bytes):
        raise ValueError(f"invalid type: '{type(pieces)}'")

    return pieces


def get_pieces_length(torrent_data: dict[str, ValueType]) -> int:
    if "info" not in torrent_data.keys():
        raise ValueError(f"missing info key: {torrent_data}")

    info = torrent_data["info"]
    if not isinstance(info, dict):
        raise ValueError(f"invalid type: '{type(info)}'")

    if "piece length" not in info.keys():
        raise ValueError(f"missing piece length key: {info}")

    piece_length = info["piece length"]
    if not isinstance(piece_length, int):
        raise ValueError(f"invalid type: '{type(piece_length)}'")

    return piece_length


def query_tracker(torrent_data: dict[str, ValueType]) -> dict[str, ValueType]:
    params = {
        "info_hash": generate_info_hash(torrent_data),
        "peer_id": "Jt9NvNvMwR9umLtQUBwj",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": get_length(torrent_data),
        "compact": 1,
    }

    query = urlencode(params)
    url = f"{get_torrent_url(torrent_data)}?{query}"
    with urllib.request.urlopen(url) as resp:
        piece_data = resp.read()

    resp = decode(piece_data)
    if resp is None:
        raise ValueError("Invalid response from tracker")

    resp, _ = resp
    if not isinstance(resp, dict):
        raise ValueError("Invalid response from tracker")

    if "failure reason" in resp.keys():
        raise ValueError(f"Failed to query tracker: {resp}")

    return resp


def get_peers(tracker_data: dict[str, ValueType]) -> list[Peer]:
    if "peers" not in tracker_data.keys():
        raise ValueError(f"Invalid response from tracker (missing peers): {tracker_data}")

    if not isinstance(tracker_data["peers"], bytes):
        raise ValueError(f"Invalid response from tracker (invalid peers). Expected bytes, got: {type(tracker_data['peers'])}")

    encoded_peers = tracker_data["peers"]
    peers: list[Peer] = []

    while len(encoded_peers) > 0:
        if len(encoded_peers) < 6:
            raise ValueError("Invalid peer data")

        peers.append(Peer.from_bytes(encoded_peers[:6]))
        encoded_peers = encoded_peers[6:]

    return peers


def parse_connection_string(connection: str) -> Tuple[str, int]:
    if ":" not in connection:
        raise ValueError("Invalid connection string")

    host, port = connection.split(":")
    port = int(port)
    return host, port


def pieces_hashes(pieces: bytes | None) -> list[bytes]:
    if pieces is None:
        raise ValueError("Invalid pieces")

    return [
        pieces[x : x + 20]
        for x
        in range(0, len(pieces), 20)
    ]


async def handle_tracker(
    peer: Peer,
    file: str,
    write_chunk: Callable[[int, int, bytes], Awaitable[None]],
    get_chunks_to_download: Callable[[bytes], Awaitable[Optional[list[ChunkMeta]]]],
    has_more_chunks_to_download: Callable[[bytes], Awaitable[bool]],
    verify_piece: Callable[[int], Awaitable[bool]],
) -> None:
    async with Tracker((peer.ip, peer.port)) as tracker:
        logger = getLogger(f"peer {peer.ip}:{peer.port}")

        # TODO: handle response
        torrent_data = decode_torrent_file(file)
        await tracker_handshake(torrent_data, tracker)
        chunks_downloading: dict[str, ChunkMeta] = {}
        available_pieces = bytes()
        unchoked = False

        while True:
            message = await tracker.listen_for_messages()

            match message:
                case Bitfield():
                    available_pieces = message.bitfield
                    logger.debug(f"Bitfield: {available_pieces}, {message.bitfield}")
                    logger.debug("Interested")
                    # TODO: check if there are pieces that are of interest
                    await tracker.send_message(Interested())
                case Unchoke():
                    unchoked = True
                    logger.debug("Unchoked")
                case Piece():
                    logger.debug(f"Piece: {message}")

                    chunk_id = f"{message.index}_{message.begin}"
                    if chunk_id not in chunks_downloading:
                        logger.error(f"Invalid chunk index: {chunk_id}")
                        raise ValueError("Invalid chunk index")

                    chunks_downloading.pop(f"{message.index}_{message.begin}")

                    await write_chunk(message.index, message.begin, message.block)

                    logger.debug(f"status: downloading={chunks_downloading}")
                    if len(chunks_downloading) == 0:
                        await verify_piece(message.index)
                case None:
                    pass
                case _:
                    logger.debug(f"Unknown message: {message}")

            if unchoked and len(chunks_downloading) == 0 and await has_more_chunks_to_download(available_pieces):
                while len(chunks_downloading) < 5:
                    chunks = await get_chunks_to_download(available_pieces)
                    if chunks is None:
                        break

                    # TODO: should be limited to five 💀
                    for chunk in chunks:
                        logger.debug(f"Downloading piece={chunk.piece_index}, begin={chunk.begin}, length={chunk.length}")
                        await tracker.start_piece_downloads(chunk.piece_index, chunk.begin, chunk.length)
                        chunks_downloading[f"{chunk.piece_index}_{chunk.begin}"] = chunk

                logger.debug(f"status: downloading={chunks_downloading}")

            if not await has_more_chunks_to_download(available_pieces) and len(chunks_downloading) == 0:
                logger.info("download complete")
                return


async def download_file(torrent_file: str, output_file: str, piece_index_to_download: int = -1):
    torrent_data = decode_torrent_file(torrent_file)
    tracker_data = query_tracker(torrent_data)
    file_length = get_length(torrent_data)
    hashes = pieces_hashes(get_pieces(torrent_data))

    pieces_length = get_pieces_length(torrent_data)
    amount_of_pieces = math.ceil(file_length / pieces_length)
    last_piece_size = file_length % pieces_length
    last_piece_index = amount_of_pieces - 1

    # shrink the file by writing the selected piece as seek 0
    if piece_index_to_download >= 0:
        seek_offset = -abs(piece_index_to_download * pieces_length)
    else:
        seek_offset = 0

    assert len(hashes) == amount_of_pieces, "Invalid amount of pieces"

    # truncate file
    with open(output_file, 'w+b'):
        pass  # File is created and truncated

    pieces = {
        x: PieceMeta(
            index=x,
            hash=hashes[x],
            length=last_piece_size if x == last_piece_index else pieces_length,
            pipeline_size=16 * 1024,
        )
        for x in range(amount_of_pieces)
        if x == piece_index_to_download or piece_index_to_download < 0
    }

    chunks = [
        chunk
        for piece in pieces.values()
        for chunk in piece.pipeline_chunks()
    ]

    global_logger.debug(f"Pieces: {pieces}")
    global_logger.debug(f"File length: {file_length}")
    global_logger.debug(f"Pieces length: {pieces_length}")
    global_logger.debug(f"Last piece size: {last_piece_size}")
    global_logger.debug(f"Last piece index: {last_piece_index}")
    global_logger.debug(f"Amount of pieces: {amount_of_pieces}")
    global_logger.debug(f"Amount of chunks: {len(chunks)}")

    peers = get_peers(tracker_data)
    # TODO: cleanup
    assert len(peers) > 0, "No peers found"

    file_lock = asyncio.Lock()
    chunk_lock = asyncio.Lock()

    async def verify_piece(piece_index: int) -> bool:
        if piece_index not in pieces.keys():
            raise ValueError(f"Invalid piece index: {piece_index}, {pieces}")

        piece = pieces[piece_index]
        async with file_lock:
            with open(output_file, "rb") as f:
                if piece_index > 0:
                    f.seek(piece_index * pieces_length + seek_offset, os.SEEK_SET)
                contents = f.read(piece.length)

        if sha1(contents).digest() != piece.hash:
            global_logger.error(f"Piece verification failed")
            await invalid_piece(piece_index)
            return False

        return True

    async def get_chunks_to_download(available_pieces: bytes) -> Optional[list[ChunkMeta]]:
        nonlocal chunks 

        async with chunk_lock:
            if len(chunks) == 0:
                return None

            chunks_to_download = [
                chunk
                for chunk in chunks
                if chunk.piece_index == chunks[0].piece_index
            ]

            chunks = [
                chunk
                for chunk in chunks
                if chunk.piece_index != chunks[0].piece_index
            ]

            return chunks_to_download

    async def has_more_chunks_to_download(available_pieces: bytes) -> bool:
        async with chunk_lock:
            return len(chunks) > 0

    async def invalid_piece(piece_index: int) -> None:
        global_logger.error(f"Invalid piece: {piece_index}. Re-adding chunks to download queue")
        piece = pieces[piece_index]

        async with chunk_lock:
            chunks.extend(piece.pipeline_chunks())

    async def write_chunk(piece_index: int, begin: int, block: bytes) -> None:
        async with file_lock:
            with open(output_file, "r+b") as f:
                # f.seek(piece_index * pieces_length + begin + seek_offset, os.SEEK_SET)
                global_logger.debug({
                    "piece_index": piece_index,
                    "pieces_length": pieces_length,
                    "begin": begin,
                    "seek_offset": seek_offset,
                    "length": len(block),
                    "seek": piece_index * pieces_length + begin + seek_offset,
                })
                f.seek(piece_index * pieces_length + begin + seek_offset, os.SEEK_SET)
                f.write(block)
                f.flush()

    tasks: set[asyncio.Task] = set()
    for peer in peers:
        tasks.add(asyncio.create_task(handle_tracker(
            peer,
            torrent_file,
            write_chunk,
            get_chunks_to_download,
            has_more_chunks_to_download,
            verify_piece,
        )))

        # TODO: disabling multiple peer usage for now
        break

    await asyncio.gather(*tasks)


def parse_magnetic_link(magnet_link: str) -> dict[str, ValueType]:
    if not magnet_link.startswith("magnet:?"):
        raise ValueError("Invalid magnet link")

    query_string = parse_qs(magnet_link[8:])

    if "xt" not in query_string.keys():
        raise ValueError("Invalid magnet link")

    if "tr" not in query_string.keys():
        raise ValueError("Invalid magnet link")

    if len(query_string["xt"]) != 1:
        raise ValueError("Invalid magnet link")

    if len(query_string["tr"]) != 1:
        raise ValueError("Invalid magnet link")

    if not query_string["xt"][0].startswith("urn:btih:"):
        raise ValueError("Invalid magnet link")

    info_hash = binascii.unhexlify(query_string["xt"][0][9:])

    return {
        "info_hash": info_hash,
        "info": {
            "length": 999,
        },
        "announce": query_string["tr"][0].encode(),
    }


def get_dict_value(data: Any, key: str, t: type[T]) -> Optional[T]:
    if data is None:
        return None

    if type(data) != dict:
        raise ValueError(f"Invalid data type: {type(data)}")

    value = data.get(key)
    if value is None:
        return None

    if type(value) != t:
        raise ValueError(f"Invalid value for key: {key}")

    return value
 

async def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    decode_cmd = subparsers.add_parser("decode")
    decode_cmd.add_argument("value", help="Bencoded value to decode")

    info_cmd = subparsers.add_parser("info")
    info_cmd.add_argument("file", help="Torrent file to parse")

    peers_cmd = subparsers.add_parser("peers")
    peers_cmd.add_argument("file", help="Torrent file to parse")

    handleshake_cmd = subparsers.add_parser("handshake")
    handleshake_cmd.add_argument("file", help="Torrent file to parse")
    handleshake_cmd.add_argument("connection", help="Connection string")

    download_piece_cmd = subparsers.add_parser("download_piece")
    download_piece_cmd.add_argument("-o", help="file to save the piece to", default="-")
    download_piece_cmd.add_argument("file", help="Torrent file to parse")
    download_piece_cmd.add_argument("piece", help="Piece index to download", default="-1")

    download_cmd = subparsers.add_parser("download")
    download_cmd.add_argument("-o", help="file to save the piece to", default="-")
    download_cmd.add_argument("file", help="Torrent file to parse")

    magnet_parse_cmd = subparsers.add_parser("magnet_parse")
    magnet_parse_cmd.add_argument("magnet_link", help="Magnet link to parse")

    magnet_handshake_cmd = subparsers.add_parser("magnet_handshake")
    magnet_handshake_cmd.add_argument("magnet_link", help="Magnet link to parse")

    magnet_info_cmd = subparsers.add_parser("magnet_info")
    magnet_info_cmd.add_argument("magnet_link", help="Magnet link to parse")

    args = parser.parse_args()

    match args.command:
        case "decode":
            # json.dumps() can't handle bytes, but bencoded "strings" need to be
            # bytestrings since they might contain non utf-8 characters.
            #
            # Let's convert them to strings for printing to the console.
            def bytes_to_str(data):
                if isinstance(data, bytes):
                    return data.decode()

                raise TypeError(f"Type not serializable: {type(data)}")

            decoded_value = decode(args.value.encode())
            if decoded_value is None:
                raise ValueError("Invalid encoded value")

            value, body = decoded_value
            if len(body) > 0:
                raise ValueError("Unable to decode all of the content. Data must have invalid encoding")

            print(json.dumps(value, default=bytes_to_str))

        case "info":
            data = decode_torrent_file(args.file)
            torrent_url = get_torrent_url(data)
            length = get_length(data)
            hashes = pieces_hashes(get_pieces(data))
            pieces_length = get_pieces_length(data)
            info_hash = generate_info_hash(data)

            print(f"Tracker URL: {torrent_url}")
            print(f"Length: {length}")
            print(f"Info Hash: {info_hash.hex()}")
            print(f"Piece Length: {pieces_length}")

            print("Piece Hashes:")
            for hash in hashes:
                print(hash.hex())

        case "peers":
            torrent_data = decode_torrent_file(args.file)
            tracker_data = query_tracker(torrent_data)

            for peer in get_peers(tracker_data):
                print(f"{peer.ip}:{peer.port}")

        case "handshake":
            conn = parse_connection_string(args.connection)

            async with Tracker(conn) as tracker:
                torrent_data = decode_torrent_file(args.file)
                resp = await tracker_handshake(torrent_data, tracker)
                print("Peer ID:", resp.peer_id.hex())

        case "download_piece":
            await download_file(args.file, args.o, int(args.piece))

        case "download":
            await download_file(args.file, args.o)

        case "magnet_parse":
            magnet_link = parse_magnetic_link(args.magnet_link)
            print("Tracker URL:", get_torrent_url(magnet_link))
            print("Info Hash:", binascii.hexlify(generate_info_hash(magnet_link)).decode())

        case "magnet_handshake":
            magnet_link = parse_magnetic_link(args.magnet_link)
            tracker_data = query_tracker(magnet_link)
            peers = get_peers(tracker_data)

            if len(peers) == 0:
                raise ValueError("No peers found")

            peer = peers[0]
            
            async with Tracker((peer.ip, peer.port)) as tracker:
                resp = await tracker_handshake(
                    magnet_link,
                    tracker,
                    b"\x00\x00\x00\x00\x00\x10\x00\x00",
                )

                print("Peer ID:", resp.peer_id.hex())

                while True:
                    message = await tracker.listen_for_messages()

                    match message:
                        case Bitfield():
                            await tracker.send_message(Extension(
                                0,
                                {
                                    "m": {
                                        "ut_metadata": 1,
                                    },
                                },
                                None,
                            ))

                        case Extension():
                            ut_metadata_id = message.m().get("ut_metadata")
                            if ut_metadata_id is not None:
                                print(f"Peer Metadata Extension ID: {ut_metadata_id}")

                            break

                        case None:
                            pass

                        case _:
                            global_logger.debug(f"Unknown message: {message}")

        case "magnet_info":
            magnet_link = parse_magnetic_link(args.magnet_link)
            tracker_data = query_tracker(magnet_link)
            peers = get_peers(tracker_data)

            if len(peers) == 0:
                raise ValueError("No peers found")

            peer = peers[0]
            
            async with Tracker((peer.ip, peer.port)) as tracker:
                print(f"Tracker URL: {get_torrent_url(magnet_link)}")
                resp = await tracker_handshake(
                    magnet_link,
                    tracker,
                    b"\x00\x00\x00\x00\x00\x10\x00\x00",
                )

                while True:
                    message = await tracker.listen_for_messages()

                    match message:
                        case Bitfield():
                            await tracker.send_message(Extension(
                                0,
                                {
                                    "m": {
                                        "ut_metadata": 1,
                                    },
                                },
                                None,
                            ))

                        case Extension():
                            if message.extension_id == 0:
                                ut_metadata_id = get_dict_value(message.m(), "ut_metadata", int)
                                if ut_metadata_id is None:
                                    continue

                                await tracker.send_message(
                                    Extension(
                                        ut_metadata_id,
                                        {
                                            "msg_type": 0,
                                            "piece": 0,
                                        },
                                         None,
                                    )
                                )
                            elif message.extension_id == 1:
                                length = get_dict_value(message.contents, "length", int)
                                piece_length = get_dict_value(message.contents, "piece length", int)
                                hashes = pieces_hashes(get_dict_value(message.contents, "pieces", bytes))

                                print(f"Length: {length}")
                                print("Info Hash:", binascii.hexlify(generate_info_hash(magnet_link)).decode())
                                print(f"Piece Length: {piece_length}")
                                print("Piece Hashes:")
                                for hash in hashes:
                                    print(hash.hex())

                                break

                        case None:
                            pass

                        case _:
                            global_logger.debug(f"Unknown message: {message}")


        case _:
            parser.print_help()
        

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
