import json
import os
import sys
from typing import Optional, Tuple
from logging import getLevelNamesMapping, getLogger, basicConfig, WARN

basicConfig(
    level=WARN,
    format="[%(filename)s:%(lineno)s - %(funcName)s()] %(message)s",
)
logger = getLogger(__name__)

log_level = getLevelNamesMapping()[os.environ.get("LOGLEVEL", "WARN")]
if log_level:
    logger.setLevel(log_level)

logger.setLevel(WARN)

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"




def decode_int(value: bytes) -> Optional[Tuple[int, bytes]]:
    if len(value) < 2:
        return None

    header, body = value[0], value[1:]
    if header != ord("i"):
        logger.debug(f"invalid integer header: '{header}'")
        return None

    logger.debug(f"body: '{body}', header: '{header}'")

    numeric = bytes()
    while len(body) > 0 and body[0] != ord("e"):
        numeric = b"".join([numeric, body[0:1]])
        body = body[1:]

    if len(body) == 0:
        logger.debug(f"no end of integer found: '{numeric}'")
        return None

    end, the_rest = body[0], body[1:]
    if end != ord("e"):
        logger.debug(f"invalid end of integer: '{end}'")
        return None

    try:
        return int(numeric), the_rest
    except ValueError:
        logger.debug(f"invalid integer value: '{numeric}'")
        return None


def decode_string(value: bytes) -> Optional[Tuple[str, bytes]]:
    str_len = bytes()

    while len(value) > 0 and value[0] != ord(":"):
        str_len += b"".join([str_len, value[0:1]])
        value = value[1:]

    if len(value) == 0 or value[0] != ord(":"):
        logger.debug(f"no colon found: '{value}'")
        return None

    try:
        length = int(str_len)
    except ValueError:
        logger.debug(f"invalid string length: '{str_len}'")
        return None

    if len(value) < length + 1:
        logger.debug(f"string length too long: '{length}' >  '{len(value)}'")
        return None

    try:
        string = value[1:length + 1].decode() 
        the_rest = value[length + 1:]
        return string, the_rest 
    except UnicodeDecodeError:
        logger.debug(f"invalid string value: '{value[1:length + 1]}'")
        return None


def decode_list(value: bytes) -> Optional[Tuple[list[int | str], bytes]]:
    header, body = value[0], value[1:]

    if header != ord("l"):
        logger.debug(f"invalid list header: '{header}'")
        return None

    logger.debug("found a list, decoding")
    
    elements = []

    while len(body) > 0 and not (len(body) == 1 and body[0] == ord("e")):
        decoded_value = decode(body)
        if decoded_value is None:
            raise ValueError("Invalid encoded value")

        element, body = decoded_value
        if element is None:
            raise ValueError("Invalid encoded value")

        if isinstance(element, list):
            raise ValueError("cannot have lists in lists")

        elements.append(element)

    if len(body) != 1 or body[0] != ord("e"):
        logger.debug(f"invalid end of list: '{body}'")
        return None

    return elements, bytes()


def decode(value: bytes) -> Optional[Tuple[str | int | list[str | int], bytes]]:
    decorder = [decode_int, decode_string, decode_list]

    for decoder in decorder:
        decoded_value = decoder(value[:])
        if decoded_value is None:
            continue

        return decoded_value

    raise ValueError(f"failed to decode value: '{value}'")



# def decode_string(value: bytes) -> Optional[str]:
#     if chr(value[0]).isdigit():
#         first_colon_index = value.find(b":")
#         if first_colon_index == -1:
#             raise ValueError("Invalid encoded value")
#         return str(value[first_colon_index+1:])
#
#     return None
#
#
# def decode_integer(value: bytes) -> Optional[int]:
#     if chr(value[0]) == "i" and chr(value[-1]) == "e":
#         try:
#             return int(value)
#         except ValueError:
#             raise ValueError("Invalid encoded value")
#
#     return None
#

# def decode(value: str) -> Optional[str | int | list[str]]:
#     decoders = [decode_string, decode_integer, decode_list]
#
#     for decoder in decoders:
#         result = decoder(value)
#         if result:
#             return result
#
#     raise NotImplementedError("Only strings and integers are supported at the moment")


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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
