import json
import os
import sys
from typing import Any, Optional, Tuple, Union
from logging import getLevelNamesMapping, getLogger, basicConfig, WARN
from hashlib import sha1
from urllib.parse import urlencode
import urllib.request

log_level = getLevelNamesMapping()[os.environ.get("LOGLEVEL", "WARN")] or WARN

basicConfig(
    level=log_level,
    format="[%(filename)s:%(lineno)s - %(funcName)s()] %(message)s",
)
logger = getLogger(__name__)

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"

ValueType = Union[int, bytes, list["ValueType"], dict[str, "ValueType"]]


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
        #.decode(encoding="mac_roman") 
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


def decode_torrent_file(file: str) -> dict:
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


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        decoded_value = decode(bencoded_value)
        if decoded_value is None:
            raise ValueError("Invalid encoded value")

        value, body = decoded_value
        if len(body) > 0:
            raise ValueError("Invalid encoded value")

        print(json.dumps(value, default=bytes_to_str))
    elif command == "info":
        file = sys.argv[2]
        data = decode_torrent_file(file)

        announce = data["announce"]
        length = data["info"]["length"]
        info = data["info"]
        pieces = info["pieces"]

        assert type(announce) == bytes
        assert type(pieces) == bytes

        print(f"Tracker URL: {announce.decode()}")
        print(f"Length: {length}")
        print(f"Info Hash: {sha1(encode(info)).hexdigest()}")
        print(f"Piece Length: {info['piece length']}")

        print("Piece Hashes:")
        while len(pieces) > 0:
            piece, pieces = pieces[:20], pieces[20:]
            print(piece.hex())

    elif command == "peers":
        file = sys.argv[2]
        data = decode_torrent_file(file)

        tracker_url = data["announce"]
        info = data["info"]
        length = info["length"]
        info_hash = sha1(encode(info)).digest()

        params = {
            "info_hash": info_hash,
            "peer_id": "Jt9NvNvMwR9umLtQUBwj",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": length,
            "compact": 1,
        }

        query = urlencode(params)
        url = f"{tracker_url.decode()}?{query}"
        with urllib.request.urlopen(url) as resp:
            piece_data = resp.read()

        resp = decode(piece_data)
        if resp is None:
            raise ValueError("Invalid response from tracker")

        resp, _ = resp
        if not isinstance(resp, dict):
            raise ValueError("Invalid response from tracker")

        if "peers" not in resp.keys():
            raise ValueError("Invalid response from tracker")

        peers = resp["peers"]

        if not isinstance(peers, bytes):
            raise ValueError("Invalid response from tracker")

        while len(peers) > 0:
            ip = ".".join([str(x) for x in peers[:4]])
            port = int.from_bytes(peers[4:6], "big")
            peers = peers[6:]

            print(f"{ip}:{port}")
        
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
