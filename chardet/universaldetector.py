"""Module containing the UniversalDetector detector class, which is the primary
class a user of ``chardet`` should use.

:author: Mark Pilgrim (initial port to Python)
:author: Shy Shalom (original C code)
:author: Dan Blanchard (major refactoring for 3.0)
:author: Ian Cordasco
"""

import codecs
import logging
import re
from typing import Dict, Optional, Union, Any
from .enums import InputState, LanguageFilter, ProbingState
from .escprober import EscCharSetProber
from .latin1prober import Latin1Prober
from .mbcsgroupprober import MBCSGroupProber
from .sbcsgroupprober import SBCSGroupProber
from .utf1632prober import UTF1632Prober


class UniversalDetector:
    from .escprober import EscCharSetProber
    from .utf1632prober import UTF1632Prober

    """The ``UniversalDetector`` class underlies the ``chardet.detect`` function
    and coordinates all of the different charset probers.

    To get a ``dict`` containing an encoding and its confidence, you can simply
    run:

    .. code::

            u = UniversalDetector()
            u.feed(some_bytes)
            u.close()
            detected = u.result

    """

    MINIMUM_THRESHOLD = 0.2
    HIGH_BYTE_DETECTOR = re.compile(b"[\x80-\xff]")
    ESC_DETECTOR = re.compile(b"(\x1b|~{)")
    WIN_BYTE_DETECTOR = re.compile(b"[\x80-\x9f]")
    ISO_WIN_MAP = {
        "iso-8859-1": "Windows-1252",
        "iso-8859-2": "Windows-1250",
        "iso-8859-5": "Windows-1251",
        "iso-8859-6": "Windows-1256",
        "iso-8859-7": "Windows-1253",
        "iso-8859-8": "Windows-1255",
        "iso-8859-9": "Windows-1254",
        "iso-8859-13": "Windows-1257",
    }

    def __init__(self, lang_filter: Union[LanguageFilter, int] = LanguageFilter.ALL):
        self._esc_charset_prober: Optional[Any] = None
        self._utf1632_prober: Optional[Any] = None
        self._charset_probers: list = []
        self.lang_filter = lang_filter
        self.result = None
        self.done = None
        self._got_data = None
        self._input_state = None
        self._last_char = None
        self.lang_filter = lang_filter
        self.logger = logging.getLogger(__name__)
        self._has_win_bytes = None
        self.reset()

    def reset(self) -> None:
        """Reset the UniversalDetector and all of its probers back to their
        initial states.  This is called by ``__init__``, so you only need to
        call this directly in between analyses of different documents.
        """
        self.result = {"encoding": None, "confidence": 0.0, "language": None}
        self.done = False
        self._got_data = False
        self._input_state = InputState.PURE_ASCII
        self._last_char = None
        self._has_win_bytes = False
        self._esc_charset_prober = None
        self._utf1632_prober = None
        self._charset_probers = []

    def feed(self, byte_str: bytes) -> None:
        """Takes a chunk of a document and feeds it through all of the relevant
        charset probers.

        After calling ``feed``, you can check the value of the ``done``
        attribute to see if you need to continue feeding the
        ``UniversalDetector`` more data, or if it has made a prediction
        (in the ``result`` attribute).

        .. note::
           You should always call ``close`` when you're done feeding in your
           document if ``done`` is not already ``True``.
        """
        if self.done:
            return

        if not len(byte_str):
            return

        if not self._got_data:
            self._got_data = True

        # First check for BOM sequences
        if not self._last_char:
            if byte_str.startswith(codecs.BOM_UTF8):
                self.result = {
                    "encoding": "UTF-8-SIG",
                    "confidence": 1.0,
                    "language": "",
                }
                self.done = True
                return
            if byte_str.startswith(codecs.BOM_UTF32_LE):
                self.result = {
                    "encoding": "UTF-32LE",
                    "confidence": 1.0,
                    "language": "",
                }
                self.done = True
                return
            if byte_str.startswith(codecs.BOM_UTF32_BE):
                self.result = {
                    "encoding": "UTF-32BE",
                    "confidence": 1.0,
                    "language": "",
                }
                self.done = True
                return
            if byte_str.startswith(codecs.BOM_UTF16_LE):
                self.result = {
                    "encoding": "UTF-16LE",
                    "confidence": 1.0,
                    "language": "",
                }
                self.done = True
                return
            if byte_str.startswith(codecs.BOM_UTF16_BE):
                self.result = {
                    "encoding": "UTF-16BE",
                    "confidence": 1.0,
                    "language": "",
                }
                self.done = True
                return

        # If none of the above, start looking at the byte sequences
        for byte in byte_str:
            if self._input_state == InputState.PURE_ASCII:
                if byte > 0x7F:
                    if byte > 0xC0:
                        self._input_state = InputState.HIGH_BYTE
                    else:
                        self._input_state = InputState.ESC_ASCII
            elif self._input_state == InputState.ESC_ASCII:
                if byte > 0x7F:
                    self._input_state = InputState.HIGH_BYTE
            elif self._input_state == InputState.HIGH_BYTE:
                if 0x80 <= byte <= 0x9F:
                    self._has_win_bytes = True

            self._last_char = byte

        if self._input_state == InputState.ESC_ASCII:
            if not self._esc_charset_prober:
                self._esc_charset_prober = EscCharSetProber(self.lang_filter)
            if (
                self._esc_charset_prober
                and self._esc_charset_prober.feed(byte_str) == ProbingState.FOUND_IT
            ):
                if (
                    hasattr(self._esc_charset_prober, "charset_name")
                    and hasattr(self._esc_charset_prober, "get_confidence")
                    and hasattr(self._esc_charset_prober, "language")
                ):
                    self.result = {
                        "encoding": self._esc_charset_prober.charset_name,
                        "confidence": self._esc_charset_prober.get_confidence(),
                        "language": self._esc_charset_prober.language,
                    }
                    self.done = True
        elif self._input_state == InputState.HIGH_BYTE:
            if not self._utf1632_prober:
                self._utf1632_prober = UTF1632Prober()
            if not self._charset_probers:
                self._charset_probers = [
                    MBCSGroupProber(self.lang_filter),
                    SBCSGroupProber(),
                    Latin1Prober(),
                ]
            for prober in [self._utf1632_prober] + self._charset_probers:
                if prober.feed(byte_str) == ProbingState.FOUND_IT:
                    self.result = {
                        "encoding": prober.charset_name,
                        "confidence": prober.get_confidence(),
                        "language": prober.language,
                    }
                    self.done = True
                    break

    def close(self) -> Dict[str, Optional[Union[str, float]]]:
        """Stop analyzing the current document and come up with a final
        prediction.

        :returns:  The ``result`` attribute, a ``dict`` with the keys
                   `encoding`, `confidence`, and `language`.
        """
        if self.done:
            return self.result
        if not self._got_data:
            self.logger.warning("no data received!")
            return self.result

        if self._input_state == InputState.PURE_ASCII:
            self.result = {"encoding": "ascii", "confidence": 1.0, "language": ""}
            return self.result

        if self._input_state == InputState.HIGH_BYTE:
            probers = (
                [self._utf1632_prober] + self._charset_probers
                if self._utf1632_prober
                else self._charset_probers
            )
            prober_confidences = [
                (prober, prober.get_confidence()) for prober in probers if prober
            ]
            if prober_confidences:
                max_prober = max(prober_confidences, key=lambda x: x[1])
                if max_prober[1] > self.MINIMUM_THRESHOLD:
                    if hasattr(max_prober[0], "charset_name") and hasattr(
                        max_prober[0], "language"
                    ):
                        self.result = {
                            "encoding": max_prober[0].charset_name,
                            "confidence": max_prober[1],
                            "language": max_prober[0].language,
                        }
            elif self._has_win_bytes:
                self.result = {
                    "encoding": "windows-1252",
                    "confidence": 0.9,
                    "language": "",
                }

        self.done = True
        return self.result if self.result["encoding"] is not None else {"encoding": None, "confidence": 0.0, "language": None}
