from abc import ABC, abstractmethod
import json
import os
from typing import Any, Optional, Tuple, Union
from logging import getLevelNamesMapping, getLogger, basicConfig, WARN
from hashlib import sha1
from urllib.parse import urlencode
import urllib.request
import argparse
from dataclasses import dataclass
import asyncio
import random
import string

log_level = getLevelNamesMapping()[os.environ.get("LOGLEVEL", "WARN")] or WARN

basicConfig(
    level=log_level,
    format="[%(filename)s:%(lineno)s - %(funcName)s()] %(message)s",
)
logger = getLogger(__name__)


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
class PeerMesage(ABC):
    message_length: int
    message_id: int
    message_payload: bytes

    @abstractmethod
    def encode(self) -> bytes:
        pass


@dataclass
class Have(PeerMesage):
    piece_index: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Have":
        length = parse_integer(data[0:4])
        if length != 5:
            raise ValueError(f"Invalid Have message length: {length}")

        id = parse_integer(data[4:5])
        if id != 4:
            raise ValueError(f"Invalid Have message id: {id}")

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
            piece_index=parse_integer(data[5:]),
        )

    def encode(self) -> bytes:
        payload = encode_integer(self.message_id) + encode_integer(self.piece_index)
        return encode_integer(len(payload)) + payload


@dataclass
class Port(PeerMesage):
    port: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Port":
        length = parse_integer(data[0:4])
        if length != 1 and length != 5:
            raise ValueError(f"Invalid Port message length: {length}")

        id = int.from_bytes(data[4:5])
        if id != 14:
            raise ValueError(f"Invalid Have message id: {id}")

        port = 0
        if length == 5:
            port = parse_integer(data[5:])

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
            port=port,
        )

    def encode(self) -> bytes:
        if self.port > 0:
            payload = encode_integer(self.message_id) + encode_integer(self.port)
            return encode_integer(len(payload)) + payload

        payload = encode_integer(self.message_id)
        return encode_integer(len(payload)) + payload


@dataclass
class Interested(PeerMesage):
    @classmethod
    def from_bytes(cls, data: bytes) -> "Interested":
        length = parse_integer(data[0:4])
        if length != 1:
            raise ValueError(f"Invalid Interested message length: {length}")

        id = parse_integer(data[4:5])
        if id != 2:
            raise ValueError(f"Invalid Interested message id: {id}")

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id)
        return encode_integer(len(payload)) + payload


@dataclass
class Unchoke(PeerMesage):
    @classmethod
    def from_bytes(cls, data: bytes) -> "Unchoke":
        length = parse_integer(data[0:4])
        if length != 1:
            raise ValueError(f"Invalid Unchoke message length: {length}")

        id = parse_integer(data[4:5])
        if id != 1:
            raise ValueError(f"Invalid Unchoke message id: {id}")

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id)
        return encode_integer(len(payload)) + payload


@dataclass
class Request(PeerMesage):
    index: int
    begin: int
    length: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Request":
        length = parse_integer(data[0:4])
        if length != 13:
            raise ValueError(f"Invalid Request message length: {length}")

        id = parse_integer(data[4:5])
        if id != 6:
            raise ValueError(f"Invalid Request message id: {id}")

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
            index=parse_integer(data[5:9]),
            begin=parse_integer(data[9:13]),
            length=parse_integer(data[13:]),
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id) \
            + encode_integer(self.index) \
            + encode_integer(self.begin) \
            + encode_integer(self.length)

        return encode_integer(len(payload)) + payload

@dataclass
class Piece(PeerMesage):
    index: int
    begin: int
    block: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "Piece":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5])
        index = parse_integer(data[5:9])
        begin = parse_integer(data[9:13])
        block = data[13:]

        return cls(
            message_length=length,
            message_id=id,
            message_payload=data[5:],
            index=index,
            begin=begin,
            block=block,
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id) \
            + encode_integer(self.index) \
            + encode_integer(self.begin) \
            + self.block

        return encode_integer(len(payload)) + payload


@dataclass
class Extended(PeerMesage):
    extended_id: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Extended":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5])
        extended_id = parse_integer(data[5:6])
        payload = data[6:]

        return cls(
            message_length=length,
            message_id=id,
            message_payload=payload,
            extended_id=extended_id,
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id) + encode_id(self.extended_id) + self.message_payload
        return encode_integer(len(payload)) + payload


@dataclass
class Bitfield(PeerMesage):
    bitfield: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "Bitfield":
        length = parse_integer(data[0:4])
        id = parse_integer(data[4:5])
        bitfield = data[5:]

        return cls(
            message_length=length,
            message_id=id,
            message_payload=bitfield,
            bitfield=bitfield,
        )

    def encode(self) -> bytes:
        payload = encode_id(self.message_id) + self.bitfield
        return encode_integer(len(payload)) + payload

def decode_peer_message(data: bytes) -> Optional[PeerMesage]:
    id = parse_integer(data[4:5])

    match id:
        case 1:
            return Unchoke.from_bytes(data)
        case 2:
            return Interested.from_bytes(data)
        case 4:
            return Have.from_bytes(data)
        case 5:
            return Bitfield.from_bytes(data)
        case 7:
            return Piece.from_bytes(data)
        case 14:
            return Port.from_bytes(data)
        case 121:
            return Extended.from_bytes(data)
        case _:
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
        logger.error(f"no end of integer found: '{numeric}'")
        return None

    end, the_rest = body[0], body[1:]
    if end != ord("e"):
        logger.error(f"invalid end of integer: '{end}'")
        return None

    try:
        return int(numeric), the_rest
    except ValueError:
        logger.error(f"invalid integer value: '{numeric}'")
        return None


def decode_string(value: bytes) -> Optional[Tuple[bytes, bytes]]:
    str_len = bytes()

    while len(value) > 0 and value[0] != ord(":"):
        str_len = b"".join([str_len, value[0:1]])
        value = value[1:]

        if str_len.isdigit() is False:
            return None

    if len(value) == 0 or value[0] != ord(":"):
        logger.error(f"no colon found: '{value}'")
        return None

    try:
        length = int(str_len.decode())
    except ValueError:
        logger.error(f"invalid string length: '{str_len}'")
        return None

    if length + 1 > len(value):
        logger.error(f"string length too long: '{length + 1} {type(length)}' >  '{len(value)}'")
        return None

    try:
        string = value[1:length + 1]
        the_rest = value[length + 1:]
        return string, the_rest 
    except UnicodeDecodeError:
        logger.error(f"invalid string encoding: '{value[1:length + 1]}'")
        return None


def decode_list(value: bytes) -> Optional[Tuple[list[ValueType], bytes]]:
    header, body = value[0], value[1:]

    if header != ord("l"):
        return None

    elements = []

    while len(body) > 0 and not body[0] == ord("e"):
        decoded_value = decode(body)
        if decoded_value is None:
            logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")

        element, body = decoded_value
        if element is None:
            logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")

        elements.append(element)

    if len(body) == 0:
        logger.error(f"invalid end of list: '{body}'")
        return None

    if body[0] != ord("e"):
        logger.error(f"invalid end of list: '{body[0]}'")
        return None

    return elements, body[1:]


def decode_dict(value: bytes) -> Optional[Tuple[dict[ValueType, ValueType], bytes]]:
    header, body = value[0], value[1:]
    if header != ord("d"):
        return None

    elements = {}

    while len(body) > 0 and not body[0] == ord("e"):
        key_value = decode(body)
        if key_value is None:
            logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")
        k, body = key_value

        if type(k) != bytes:
            logger.error(f"Invalid key type: '{k}'")
            raise ValueError("Invalid key type")

        k = k.decode()

        value_value = decode(body)
        if value_value is None:
            logger.error(f"Invalid encoded value: '{body}'")
            raise ValueError("Invalid encoded value")
        v, body = value_value

        elements[k] = v

    if len(body) == 0:
        logger.error(f"invalid end of dict: '{body}'")
        return None

    if body[0] != ord("e"):
        logger.error(f"invalid end of dict: '{body[0]}'")
        return None

    return elements, body[1:]


def decode(value: bytes) -> Optional[Tuple[ValueType, bytes]]:
    decorder = [decode_int, decode_string, decode_list, decode_dict]

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
    info = torrent_data["info"]
    info_hash = sha1(encode(info))
    return info_hash.digest()


def parse_integer(data: bytes) -> int:
    return int.from_bytes(data, "big")


def encode_integer(data: int) -> bytes:
    return data.to_bytes(4, "big")


def encode_id(id: int) -> bytes:
    return id.to_bytes(1, "big")


class Tracker(object):
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _conn: tuple[str, int]

    def __init__(self, conn: tuple[str, int]) -> None:
        self._conn = conn

    async def _connect(self, conn: tuple[str, int]) -> None:
        self._reader, self._writer = await asyncio.open_connection(conn[0], conn[1])

    async def handshake(self, info_hash: bytes, peer_id: bytes) -> TrackerPeersResponse:
        # TODO: could this be a peer message instead?
        # Unsure if it can because the message begins with with the number
        # 19, which is the length of the protocol string. The length of the
        # protocol is 68 bytes, which doesn't make sense for the prefix.
        # 19 bytes returns the protocol string 'BitTorrent protocol' which
        # is then followed by the reserved bytes, info hash, and peer id.
        # Would we read the payload which is the protocol string and then
        # read another 49 bytes to get the rest of the message?

        h = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00" \
            + info_hash \
            + peer_id

        self._writer.write(h)
        await self._writer.drain()

        return TrackerPeersResponse.from_bytes(await self._reader.read(68))

    async def listen_for_messages(self) -> Optional[PeerMesage]:
        message_length_bytes = await self._reader.read(4)
        if len(message_length_bytes) == 0:
            return None

        # TODO: sanity check message length
        message_length = parse_integer(message_length_bytes)
        if message_length == 0:
            logger.error(f"Invalid message length: {message_length_bytes}")
            return None

        return decode_peer_message(
            message_length_bytes + await self._reader.read(message_length)
        )

    async def send_message(self, message: PeerMesage) -> None:
        print("Sending message:", message, message.encode())
        self._writer.write(message.encode())
        await self._writer.drain()


    async def __aenter__(self):
        await self._connect(self._conn)
        return self

    async def __aexit__(self, *_) -> None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            logger.exception("Failed to close connection")


def generate_peer_id() -> bytes:
    prefix = "-MW0001-"
    random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return (prefix + random_part).encode("utf-8")


async def tracker_handshake(file: str, tracker: Tracker) -> TrackerPeersResponse:
    torrent_data = decode_torrent_file(file)
    info_hash = generate_info_hash(torrent_data)
    peer_id = generate_peer_id()
    return await tracker.handshake(info_hash, peer_id)


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

    return resp


def get_peers(tracker_data: dict[str, ValueType]) -> list[Peer]:
    if "peers" not in tracker_data.keys():
        raise ValueError("Invalid response from tracker")

    if not isinstance(tracker_data["peers"], bytes):
        raise ValueError("Invalid response from tracker")

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
    download_piece_cmd.add_argument("piece", help="Piece index to download")

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
            pieces = get_pieces(data)
            pieces_length = get_pieces_length(data)
            info_hash = generate_info_hash(data)

            print(f"Tracker URL: {torrent_url}")
            print(f"Length: {length}")
            print(f"Info Hash: {info_hash.hex()}")
            print(f"Piece Length: {pieces_length}")

            print("Piece Hashes:")
            while len(pieces) > 0:
                piece, pieces = pieces[:20], pieces[20:]
                print(piece.hex())

        case "peers":
            torrent_data = decode_torrent_file(args.file)
            tracker_data = query_tracker(torrent_data)

            for peer in get_peers(tracker_data):
                print(f"{peer.ip}:{peer.port}")

        case "handshake":
            conn = parse_connection_string(args.connection)

            async with Tracker(conn) as tracker:
                resp = await tracker_handshake(args.file, tracker)
                print("Peer ID:", resp.peer_id.hex())

        case "download_piece":
            # TODO: validate piece index is within bounds
            piece_index = int(args.piece)
            output_file = args.o

            torrent_data = decode_torrent_file(args.file)
            torrent_url = get_torrent_url(torrent_data)
            tracker_data = query_tracker(torrent_data)
            file_length = get_length(torrent_data)
            pieces_length = get_pieces_length(torrent_data)
            last_piece_size = file_length % pieces_length
            last_piece_index = file_length // pieces_length

            print("File length:", file_length)
            print("Pieces length:", pieces_length)
            print("Last piece size:", last_piece_size)
            print("Last piece index:", last_piece_index)

            peers = get_peers(tracker_data)
            # TODO: cleanup
            assert len(peers) > 0, "No peers found"
            peer = peers[0]

            async with Tracker((peer.ip, peer.port)) as tracker:
                resp = await tracker_handshake(args.file, tracker)

                while True:
                    message = await tracker.listen_for_messages()
                    if message is None:
                        continue

                    print("Message:\n", message)
                    if isinstance(message, Bitfield):
                        await tracker.send_message(Interested(1, 2, b""))

                    elif isinstance(message, Unchoke):
                        piece_block_size = pieces_length
                        if piece_index == last_piece_index:
                            piece_block_size = last_piece_size
                        
                        await tracker.send_message(Request(
                            13,
                            6,
                            b"",
                            piece_index,
                            piece_index * pieces_length,
                            piece_block_size,
                        ))

                    elif isinstance(message, Piece):
                        # TODO: validate sha1 hash of piece
                        print("Piece received")

                        if output_file == "-":
                            print(message.block)
                        else:
                            with open(output_file, "ab") as f:
                                f.seek(piece_index * pieces_length)
                                f.write(message.block)
                                f.flush()

                        break

        case _:
            parser.print_help()
        

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
