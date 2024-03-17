from enum import Enum, auto


class RetTypes(Enum):
    OK = auto()
    SKIP = auto()
    LLM_ERROR = auto()
    UNFOUND_ERROR = auto()
    NO_SPEC_ERROR = auto()
