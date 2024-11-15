from typing import Union
from .charsetprober import CharSetProber
from .enums import ProbingState


class UTF1632Prober(CharSetProber):
    def _check_encoding(self) -> bool:
        total_chars = sum(self.zeros_at_mod) + sum(self.nonzeros_at_mod)
        if total_chars < self.MIN_CHARS_FOR_DETECTION:
            return False

        utf32_be_ratio = (
            self.zeros_at_mod[0] + self.zeros_at_mod[1] + self.zeros_at_mod[2]
        ) / total_chars
        utf32_le_ratio = (
            self.zeros_at_mod[1] + self.zeros_at_mod[2] + self.zeros_at_mod[3]
        ) / total_chars
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

    def get_confidence(self) -> float:
        """Return the confidence of the prober."""
        if self.state == ProbingState.FOUND_IT:
            return 0.99
        elif self.state == ProbingState.NOT_ME:
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
        self.quad = [0, 0, 0, 0]
        self.invalid_utf16be = False
        self.invalid_utf16le = False
        self.invalid_utf32be = False
        self.invalid_utf32le = False
        self.first_half_surrogate_pair_detected_16be = False
        self.first_half_surrogate_pair_detected_16le = False
        self.reset()

    def reset(self) -> None:
        """Reset the prober state."""
        CharSetProber.reset(self)
        self.position = 0
        self.zeros_at_mod = [0] * 4
        self.nonzeros_at_mod = [0] * 4
        self.quad = [0, 0, 0, 0]
        self.invalid_utf16be = False
        self.invalid_utf16le = False
        self.invalid_utf32be = False
        self.invalid_utf32le = False
        self.first_half_surrogate_pair_detected_16be = False
        self.first_half_surrogate_pair_detected_16le = False

    def feed(self, byte_str: Union[bytes, bytearray]) -> ProbingState:
        """Feed a chunk of data through the prober."""
        if self.state == ProbingState.NOT_ME:
            return self.state

        for byte in byte_str:
            self.quad[self.position % 4] = byte
            if byte == 0:
                self.zeros_at_mod[self.position % 4] += 1
            else:
                self.nonzeros_at_mod[self.position % 4] += 1

            if self.position % 4 == 3:
                if not self.invalid_utf32be:
                    self.invalid_utf32be = not self.validate_utf32_characters(
                        bytes(self.quad)
                    )
                if not self.invalid_utf32le:
                    self.invalid_utf32le = not self.validate_utf32_characters(
                        bytes(reversed(self.quad))
                    )

            if self.position % 2 == 1:
                if not self.invalid_utf16be:
                    pair = bytes(
                        self.quad[(self.position - 1) % 4 : (self.position + 1) % 4]
                    )
                    if not self.validate_utf16_characters(pair):
                        self.invalid_utf16be = True
                    elif 0xD800 <= int.from_bytes(pair, byteorder="big") <= 0xDBFF:
                        self.first_half_surrogate_pair_detected_16be = True
                    elif 0xDC00 <= int.from_bytes(pair, byteorder="big") <= 0xDFFF:
                        if not self.first_half_surrogate_pair_detected_16be:
                            self.invalid_utf16be = True
                        self.first_half_surrogate_pair_detected_16be = False

                if not self.invalid_utf16le:
                    pair = bytes(
                        reversed(
                            self.quad[(self.position - 1) % 4 : (self.position + 1) % 4]
                        )
                    )
                    if not self.validate_utf16_characters(pair):
                        self.invalid_utf16le = True
                    elif 0xD800 <= int.from_bytes(pair, byteorder="big") <= 0xDBFF:
                        self.first_half_surrogate_pair_detected_16le = True
                    elif 0xDC00 <= int.from_bytes(pair, byteorder="big") <= 0xDFFF:
                        if not self.first_half_surrogate_pair_detected_16le:
                            self.invalid_utf16le = True
                        self.first_half_surrogate_pair_detected_16le = False

            self.position += 1

            if self.position >= self.MIN_CHARS_FOR_DETECTION:
                if self._check_encoding():
                    self.state = ProbingState.FOUND_IT
                    break

        return self.state

    def validate_utf32_characters(self, quad: bytes) -> bool:
        """Validate if the quad of bytes is valid UTF-32.

        UTF-32 is valid in the range 0x00000000 - 0x0010FFFF
        excluding 0x0000D800 - 0x0000DFFF

        https://en.wikipedia.org/wiki/UTF-32
        """
        value = int.from_bytes(quad, byteorder="big")
        return 0 <= value <= 0x10FFFF and not (0xD800 <= value <= 0xDFFF)

    def validate_utf16_characters(self, pair: bytes) -> bool:
        """Validate if the pair of bytes is  valid UTF-16.

        UTF-16 is valid in the range 0x0000 - 0xFFFF excluding 0xD800 - 0xFFFF
        with an exception for surrogate pairs, which must be in the range
        0xD800-0xDBFF followed by 0xDC00-0xDFFF

        https://en.wikipedia.org/wiki/UTF-16
        """
        value = int.from_bytes(pair, byteorder="big")
        if 0xD800 <= value <= 0xDBFF:
            # First half of a surrogate pair
            return True
        elif 0xDC00 <= value <= 0xDFFF:
            # Second half of a surrogate pair
            return True
        else:
            # Regular character
            return 0 <= value < 0xD800 or 0xE000 <= value <= 0xFFFF
