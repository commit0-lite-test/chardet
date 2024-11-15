from .charsetprober import CharSetProber
from .enums import ProbingState

class UTF1632Prober(CharSetProber):
    def _check_encoding(self):
        total_chars = sum(self.zeros_at_mod) + sum(self.nonzeros_at_mod)
        if total_chars < self.MIN_CHARS_FOR_DETECTION:
            return False

        utf32_be_ratio = (self.zeros_at_mod[0] + self.zeros_at_mod[1] + self.zeros_at_mod[2]) / total_chars
        utf32_le_ratio = (self.zeros_at_mod[1] + self.zeros_at_mod[2] + self.zeros_at_mod[3]) / total_chars
        utf16_be_ratio = (self.zeros_at_mod[0] + self.zeros_at_mod[1]) / total_chars
        utf16_le_ratio = (self.zeros_at_mod[1] + self.zeros_at_mod[2]) / total_chars

        if utf32_be_ratio > self.EXPECTED_RATIO and not self.invalid_utf32be:
            self._charset_name = "UTF-32BE"
            return True
        elif utf32_le_ratio > self.EXPECTED_RATIO and not self.invalid_utf32le:
            self._charset_name = "UTF-32LE"
            return True
        elif utf16_be_ratio > self.EXPECTED_RATIO and not self.invalid_utf16be:
            self._charset_name = "UTF-16BE"
            return True
        elif utf16_le_ratio > self.EXPECTED_RATIO and not self.invalid_utf16le:
            self._charset_name = "UTF-16LE"
            return True

        return False

    def get_confidence(self):
        if self._state == ProbingState.FOUND_IT:
            return 0.99
        elif self._state == ProbingState.NOT_ME:
            return 0.01
        else:
            return 0.5
    """
    This class simply looks for occurrences of zero bytes, and infers
    whether the file is UTF16 or UTF32 (low-endian or big-endian)
    For instance, files looking like ( \x00 \x00 \x00 [nonzero] )+
    have a good probability to be UTF32BE.  Files looking like ( \x00 [nonzero] )+
    may be guessed to be UTF16BE, and inversely for little-endian varieties.
    """
    MIN_CHARS_FOR_DETECTION = 20
    EXPECTED_RATIO = 0.94

    def __init__(self):
        super().__init__()
        self.position = 0
        self.zeros_at_mod = [0] * 4
        self.nonzeros_at_mod = [0] * 4
        self._state = ProbingState.DETECTING
        self.quad = [0, 0, 0, 0]
        self.invalid_utf16be = False
        self.invalid_utf16le = False
        self.invalid_utf32be = False
        self.invalid_utf32le = False
        self.first_half_surrogate_pair_detected_16be = False
        self.first_half_surrogate_pair_detected_16le = False
        self.reset()

    def validate_utf32_characters(self, quad):
        """
        Validate if the quad of bytes is valid UTF-32.

        UTF-32 is valid in the range 0x00000000 - 0x0010FFFF
        excluding 0x0000D800 - 0x0000DFFF

        https://en.wikipedia.org/wiki/UTF-32
        """
        value = int.from_bytes(quad, byteorder='big')
        return 0 <= value <= 0x10FFFF and not (0xD800 <= value <= 0xDFFF)

    def validate_utf16_characters(self, pair):
        """
        Validate if the pair of bytes is  valid UTF-16.

        UTF-16 is valid in the range 0x0000 - 0xFFFF excluding 0xD800 - 0xFFFF
        with an exception for surrogate pairs, which must be in the range
        0xD800-0xDBFF followed by 0xDC00-0xDFFF

        https://en.wikipedia.org/wiki/UTF-16
        """
        value = int.from_bytes(pair, byteorder='big')
        if 0xD800 <= value <= 0xDBFF:
            # First half of a surrogate pair
            return True
        elif 0xDC00 <= value <= 0xDFFF:
            # Second half of a surrogate pair
            return True
        else:
            # Regular character
            return 0 <= value < 0xD800 or 0xE000 <= value <= 0xFFFF
