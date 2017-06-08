from typing import Union


def ones_complement_checksum(msg: Union[bytes, bytearray]):
    """
    Calculate the 16-bit one's complement of the one's complement sum of a message.

    :param msg: The message
    :return: The checksum
    """
    checksum = 0
    for i in range(0, len(msg), 2):
        current_word = (msg[i] << 8) + msg[i + 1]

        # Carry around add
        c = checksum + current_word
        checksum = (c & 0xffff) + (c >> 16)

    return ~checksum & 0xffff
