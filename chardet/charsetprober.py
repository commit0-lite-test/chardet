import logging
from typing import Optional, Union
import re

INTERNATIONAL_WORDS_PATTERN = re.compile(
    b"[a-zA-Z]*[\x80-\xff]+[a-zA-Z]*[^a-zA-Z\x80-\xff]?"
)


class CharSetProber:
    SHORTCUT_THRESHOLD = 0.95

    def __init__(self, lang_filter: Optional[str] = None):
        self._state: Optional[str] = None
        self.lang_filter = lang_filter
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def filter_international_words(buf: Union[bytes, bytearray]) -> bytes:
        r"""We define three types of bytes:
        alphabet: english alphabets [a-zA-Z]
        international: international characters [\x80-ÿ]
        marker: everything else [^a-zA-Z\x80-ÿ]
        The input buffer can be thought to contain a series of words delimited
        by markers. This function works to filter all words that contain at
        least one international character. All contiguous sequences of markers
        are replaced by a single space ascii character.
        This filter applies to all scripts which do not use English characters.
        """
        filtered = INTERNATIONAL_WORDS_PATTERN.sub(b" ", buf)
        return filtered

    @staticmethod
    def remove_xml_tags(buf: Union[bytes, bytearray]) -> bytes:
        """Returns a copy of ``buf`` that retains only the sequences of English
        alphabet and high byte characters that are not between <> characters.
        This filter can be applied to all scripts which contain both English
        characters and extended ASCII characters, but is currently only used by
        ``Latin1Prober``.
        """
        inside_tag = False
        filtered = bytearray()
        for byte in buf:
            if byte == ord(b"<"):
                inside_tag = True
            elif byte == ord(b">"):
                inside_tag = False
            elif not inside_tag:
                filtered.append(byte)
        return bytes(filtered)
