#!/usr/bin/env python3

# Authors and sources:
# https://github.com/Tonygratta/scapy-iec101
 
from typing import Any, Optional
from scapy.packet import Packet  # type: ignore
from scapy.fields import (  # type: ignore
    Field,
    XBitField,
    XByteField,
    XByteEnumField,
    XLEShortField,
    ByteField,
    BitField,
    BitEnumField,
    IEEEFloatField,
    LEThreeBytesField,
    LEShortField,
    LESignedShortField,
    LESignedIntField,
    LEX3BytesField,
    FlagsField,
    PacketLenField,
    FieldLenField,
    StrLenField,
    PacketField,
    XStrField,
    MultipleTypeField,
    FieldListField,
    PacketListField,
)

FUNCTION_CODES = {
    0x0: "SEND/CONFIRM - Reset of remote link",
    0x1: "SEND/CONFIRM - Reset of user process",
    0x2: "SEND/CONFIRM - Reserved for balanced transmission procedure",
    0x3: "SEND/CONFIRM - User data",
    0x4: "SEND/NO REPLY - User data",
    0x5: "Reserved",
    0x6: "Reserved for special use by agreement",
    0x7: "Reserved for special use by agreement",
    0x8: "REQUEST for access demand",
    0x9: "REQUEST/RESPONSE - Status of link",
    0xA: "REQUEST/RESPONSE - User data class 1",
    0xB: "REQUEST/RESPONSE - User data class 2",
    0xC: "Reserved",
    0xD: "Reserved",
    0xE: "Reserved for special use by agreement",
    0xF: "Reserved for special use by agreement",
}

TYPEID_ASDU = {
    0x01: "M_SP_NA_1 (1)",
    0x02: "M_SP_TA_1 (2)",
    0x03: "M_DP_NA_1 (3)",
    0x04: "M_DP_TA_1 (4)",
    0x05: "M_ST_NA_1 (5)",
    0x06: "M_ST_TA_1 (6)",
    0x07: "M_BO_NA_1 (7)",
    0x08: "M_BO_TA_1 (8)",
    0x09: "M_ME_NA_1 (9)",
    0x0A: "M_ME_TA_1 (10)",
    0x0B: "M_ME_NB_1 (11)",
    0x0C: "M_ME_TB_1 (12)",
    0x0D: "M_ME_NC_1 (13)",
    0x0E: "M_ME_TC_1 (14)",
    0x0F: "M_IT_NA_1 (15)",
    0x10: "M_IT_TA_1 (16)",
    0x11: "M_EP_TA_1 (17)",
    0x12: "M_EP_TB_1 (18)",
    0x13: "M_EP_TC_1 (19)",
    0x14: "M_PS_NA_1 (20)",
    0x15: "M_ME_ND_1 (21)",
    0x1E: "M_SP_TB_1 (30)",
    0x1F: "M_DP_TB_1 (31)",
    0x20: "M_ST_TB_1 (32)",
    0x21: "M_BO_TB_1 (33)",
    0x22: "M_ME_TD_1 (34)",
    0x23: "M_ME_TE_1 (35)",
    0x24: "M_ME_TF_1 (36)",
    0x25: "M_IT_TB_1 (37)",
    0x26: "M_EP_TD_1 (38)",
    0x27: "M_EP_TE_1 (39)",
    0x28: "M_EP_TF_1 (40)",
    0x2D: "C_SC_NA_1 (45)",
    0x2E: "C_DC_NA_1 (46)",
    0x2F: "C_RC_NA_1 (47)",
    0x30: "C_SE_NA_1 (48)",
    0x31: "C_SE_NB_1 (49)",
    0x32: "C_SE_NC_1 (50)",
    0x33: "C_BO_NA_1 (51)",
    0x46: "M_EI_NA_1 (70)",
    0x64: "C_IC_NA_1 (100)",
    0x65: "C_CI_NA_1 (101)",
    0x66: "C_RD_NA_1 (102)",
    0x67: "C_CS_NA_1 (103)",
    0x68: "C_TS_NA_1 (104)",
    0x69: "C_RP_NA_1 (105)",
    0x6A: "C_CD_NA_1 (106)",
    0x6E: "P_ME_NA_1 (110)",
    0x6F: "P_ME_NB_1 (111)",
    0x70: "P_ME_NC_1 (112)",
    0x71: "P_AC_NA_1 (113)",
    0x78: "F_FR_NA_1 (120)",
    0x79: "F_SR_NA_1 (121)",
    0x7A: "F_SC_NA_1 (122)",
    0x7B: "F_LS_NA_1 (123)",
    0x7C: "F_AF_NA_1 (124)",
    0x7D: "F_SG_NA_1 (125)",
    0x7E: "F_DR_TA_1 (126)",
}

CAUSE_OF_TX = {
    0: "not used",
    1: "per/cyc",
    2: "back",
    3: "spont",
    4: "init",
    5: "req",
    6: "Act",
    7: "ActCon",
    8: "Deact",
    9: "DeactCon",
    10: "ActTerm",
    11: "retrem",
    12: "retloc",
    13: "file",
    20: "inrogen",
    21: "inro1",
    22: "inro2",
    23: "inro3",
    24: "inro4",
    25: "inro5",
    26: "inro6",
    27: "inro7",
    28: "inro8",
    29: "inro9",
    30: "inro10",
    31: "inro11",
    32: "inro12",
    33: "inro13",
    34: "inro14",
    35: "inro15",
    36: "inro16",
    37: "reqcogen",
    38: "reqco1",
    39: "reqco2",
    40: "reqco3",
    41: "reqco4",
    44: "unknown type identification",
    45: "unknown cause of transmission",
    46: "unknown common address of ASDU",
    47: "unknown information object address",
}

SQ_ENUM = {0: "Single", 1: "Sequence"}

SC_ENUM = {0: "OFF", 1: "ON"}

DC_ENUM = {0: "not permitted", 1: "OFF", 2: "ON", 3: "not permitted"}

SE_ENUM = {0: "Execute", 1: "Select"}

DPI_ENUM = {0: "Indeterminate/intermidiate", 1: "OFF", 2: "ON", 3: "Indeterminate"}

ES_ENUM = {
    0: "Indeterminate (0)",
    1: "OFF",
    2: "ON",
    3: "Indeterminate (3)",
}

DOW_ENUM = {
    0: "not used",
    1: "Monday",
    2: "Tuesday",
    3: "Wednesday",
    4: "Thursday",
    5: "Friday",
    6: "Saturday",
    7: "Sunday",
}

RCS_ENUM = {
    0: "not permitted",
    1: "next step LOWER",
    2: "next step HIGHER",
    3: "not permitted",
}

COI_ENUM = {
    0: "local power switch on",
    1: "local manual reset",
    2: "remote reset",
}
COI_ENUM.update({x: "reserved (compatible)" for x in range(3, 32)})
COI_ENUM.update({x: "reserved (private)" for x in range(32, 128)})

QOI_ENUM = {
    0: "not used",
    20: "Station interrogation (global)",
    21: "Interrogation of group 1",
    22: "Interrogation of group 2",
    23: "Interrogation of group 3",
    24: "Interrogation of group 4",
    25: "Interrogation of group 5",
    26: "Interrogation of group 6",
    27: "Interrogation of group 7",
    28: "Interrogation of group 8",
    29: "Interrogation of group 9",
    30: "Interrogation of group 10",
    31: "Interrogation of group 11",
    32: "Interrogation of group 12",
    33: "Interrogation of group 13",
    34: "Interrogation of group 14",
    35: "Interrogation of group 15",
    36: "Interrogation of group 16",
}
QOI_ENUM.update({x: "Reserved (compatible range)" for x in range(1, 20)})
QOI_ENUM.update({x: "Reserved (compatible range)" for x in range(37, 64)})
QOI_ENUM.update({x: "Reserved (private)" for x in range(64, 256)})

RQT_ENUM = {
    0: "no counter requested (not used)",
    1: "request counter group 1",
    2: "request counter group 2",
    3: "request counter group 3",
    4: "request counter group 4",
    5: "general request counter",
}
RQT_ENUM.update({x: "Reserved (compatible range)" for x in range(6, 32)})
RQT_ENUM.update({x: "Reserved (private)" for x in range(32, 64)})

QRP_ENUM = {
    0: "not used",
    1: "general reset of process",
    2: "reset of pending information with time tag of the event buffer",
}
QRP_ENUM.update({x: "Reserved (compatible range)" for x in range(3, 128)})
QRP_ENUM.update({x: "Reserved (private)" for x in range(128, 256)})

FRZ_ENUM = {
    0: "read",
    1: "counter freeze without reset",
    2: "counter freeze with reset",
    3: "counter reset",
}

KPA_ENUM = {
    0: "not used",
    1: "threshold value",
    2: "smoothing factor",
    3: "low limit",
    4: "high limit",
}
KPA_ENUM.update({x: "Reserved (compatible range)" for x in range(5, 32)})
KPA_ENUM.update({x: "Reserved (private)" for x in range(32, 64)})

QPA_ENUM = {
    0: "not used",
    1: "previously loaded parameters",
    2: "parameter of the addressed object",
    3: "persistent cyclic or periodic transmission",
}
QPA_ENUM.update({x: "Reserved (compatible range)" for x in range(4, 128)})
QPA_ENUM.update({x: "Reserved (private)" for x in range(128, 256)})

FRQ_ENUM = {0: "default"}
FRQ_ENUM.update({x: "Reserved (compatible range)" for x in range(1, 64)})
FRQ_ENUM.update({x: "Reserved (private)" for x in range(64, 128)})

SRQ_ENUM = FRQ_ENUM

SCQ_ENUM_A = {
    0: "default",
    1: "select file",
    2: "request file",
    3: "deactivate file",
    4: "delete file",
    5: "select section",
    6: "request section",
    7: "deactivate section",
}
SCQ_ENUM_A.update({x: "Reserved (compatible range)" for x in range(8, 11)})
SCQ_ENUM_A.update({x: "Reserved (private)" for x in range(11, 16)})

SCQ_ENUM_B = {
    0: "default",
    1: "requested memory space not available",
    2: "checksum failed",
    3: "unexpected communication service",
    4: "unexpected name of file",
    5: "unexpected name of section",
}
SCQ_ENUM_B.update({x: "Reserved (compatible range)" for x in range(6, 11)})
SCQ_ENUM_B.update({x: "Reserved (private)" for x in range(11, 16)})

LSQ_ENUM = {
    0: "not used",
    1: "file transfer without deactivation",
    2: "file transfer with deactivation",
    3: "section transfer without deactivation",
    4: "section transfer with deactivation",
}
LSQ_ENUM.update({x: "Reserved (compatible range)" for x in range(5, 128)})
LSQ_ENUM.update({x: "Reserved (private)" for x in range(128, 256)})

AFQ_ENUM_A = {
    0: "not used",
    1: "positive acknowledge of file transfer",
    2: "negative acknowledge of file transfer",
    3: "positive acknowledge of section transfer",
    4: "negative acknowledge of section transfer",
}
AFQ_ENUM_A.update({x: "Reserved (compatible range)" for x in range(5, 11)})
AFQ_ENUM_A.update({x: "Reserved (private)" for x in range(11, 16)})

AFQ_ENUM_B = SCQ_ENUM_B

SOF_ENUM = {0: "default"}
SOF_ENUM.update({x: "Reserved (compatible range)" for x in range(1, 16)})
SOF_ENUM.update({x: "Reserved (compatible range)" for x in range(16, 32)})

CAUSE_OF_TX_FLAGS = {1: "Negative", 2: "Test"}

CONTROL_FLAGS = {1: "FCV", 2: "FCB", 3: "PRM", 4: "RES"}

SIQ_FLAGS = {1: "SPI", 5: "BL", 6: "SB", 7: "NT", 8: "IV"}

DIQ_FLAGS = {3: "BL", 4: "SB", 5: "NT", 6: "IV"}

QDS_FLAGS = {
    1: "OV",
    5: "BL",
    6: "SB",
    7: "NT",
    8: "IV",
}

BCR_FLAGS = {
    1: "CY",
    2: "CA",
    3: "IV",
}

SEP_FLAGS = {
    1: "EI",
    2: "BL",
    3: "SB",
    4: "NT",
    5: "IV",
}

SPE_FLAGS = {
    1: "GS",
    2: "SL1",
    3: "SL2",
    4: "SL3",
    5: "SIE",
    6: "SRD",
}

QDP_FLAGS = {
    4: "EI",
    5: "BL",
    6: "SB",
    7: "NT",
    8: "IV",
}

OCI_FLAGS = {
    1: "GC",
    2: "CL1",
    3: "CL2",
    4: "CL3",
}

LPCPOP_FLAGS = {1: "LPC", 2: "POP"}

SOF_FLAGS = {1: "LFD", 2: "FOR", 3: "FA"}


class LEIEEEFloatField(Field):
    """
    little endian IEEE float field
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<f")


class NVA(Field):
    def __init__(self, name: str, default: Any, fmt: str = "<e") -> None:
        super().__init__(name, default, fmt)


class BBitField(BitField):
    def i2repr(self, pkt, x) -> str:
        return f"0b{self.i2h(pkt, x):0{self.size}b}"


class CP24Time2a(Packet):
    name = "CP24Time2a"
    fields_desc = [
        LEShortField("Milliseconds", 0x0000),
        BitEnumField("IV", 0, 1, {0: "valid", 1: "invalid"}),
        BitEnumField("GEN", 0, 1, {0: "genuine", 1: "substituted"}),
        BitField("minute", 0, 6),
    ]

    def extract_padding(self, s: bytes):
        return b"", s


class CP56Time2a(Packet):
    name = "Seven octet binary time"
    fields_desc = [
        LEShortField("milliseconds", 0x0000),
        BitField("IV", 0b0, 1),
        BitField("GEN", 0b0, 1),
        BitField("minute", 0b000000, 6),
        BitField("SU", 0b0, 1),
        BitField("RES2", 0b00, 2),
        BitField("hour", 0b00000, 5),
        BitEnumField("DOW", 0x000, 3, DOW_ENUM),
        BitField("day", 0b00001, 5),
        BitField("RES3", 0x0, 4),
        BitField("month", 0x1, 4),
        BitField("RES4", 0b0, 1),
        BitField("year", 0b0000000, 7),
    ]

    def extract_padding(self, s: bytes):
        return b"", s


class SOF(Packet):
    name = "Status of file"
    fields_desc = [
        FlagsField("flags", 0b000, 3, SOF_FLAGS),
        BitEnumField("status", 0b00000, 5, SOF_ENUM),
    ]


class IOFile(Packet):
    name = "entry"
    fields_desc = [
        LEShortField("NOF", 0x0000),
        LEThreeBytesField("LOF", 0x000000),
        PacketField("SOF", SOF(), SOF),
        PacketField("created", CP56Time2a(), CP56Time2a),
    ]


class IOVal(Packet):
    name = "Information object value"

    def extract_padding(self, s: bytes):
        return b"", s


class VSQ(IOVal):
    name = "Variable Structure Qualifier"
    fields_desc = [BitEnumField("SQ", 0x0, 1, SQ_ENUM), BitField("number", 0x0, 7)]


class DIQ(IOVal):
    name = "Double-point information with quality descriptor"
    fields_desc = [
        FlagsField("quality", 0b000000, 6, DIQ_FLAGS),
        BitEnumField("DPI", 0b11, 2, DPI_ENUM),
    ]


class StepPosition(IOVal):
    fields_desc = [
        BitField("transient", 0b0, 1),
        BitField("value", 0b0000000, 7),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class Bitstring32(IOVal):
    name = "Bitstring 32 bit"
    fields_desc = [
        XBitField("BSI", 0x00, 32),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class NormalizedValue(IOVal):
    name = "Normalized value"
    fields_desc = [
        NVA("NVA", 0.0),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class ScaledValue(IOVal):
    name = "Scaled value"
    fields_desc = [
        LESignedShortField("SVA", 0x0000),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class ShortFloat(IOVal):
    name = "Short floating point number"
    fields_desc = [
        LEIEEEFloatField("value", 0.0),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class BCR(IOVal):
    name = "Binary counter reading"
    fields_desc = [
        LESignedIntField("value", 0),
        FlagsField("flags", 0b000, 3, BCR_FLAGS),
        BitField("sequence", 0b00000, 5),
    ]


class StatusChange(IOVal):
    name = "Status change detection"
    fields_desc = [
        BBitField("status", 0x0000, 16),
        BBitField("change", 0x0000, 16),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
    ]


class VTI(IOVal):
    name = "Value with transient Value state indication"
    fields_desc = [
        BitField("transient", 0b0, 1),
        BitField("value", 0b0000000, 7),
    ]


class QCC(IOVal):
    name = "Qualifier of counter interrogation command"
    fields_desc = [
        BitEnumField("FRZ", 0b00, 2, FRZ_ENUM),
        BitEnumField("RQT", 0b000000, 6, RQT_ENUM),
    ]


class QPM(IOVal):
    name = "Qualifier of parameter of measured values"
    fields_desc = [
        FlagsField("parameter", 0b00, 2, LPCPOP_FLAGS),
        BitEnumField("KPA", 0b000000, 6, KPA_ENUM),
    ]


class FRQ(IOVal):
    name = "File ready qualifier"
    fields_desc = [
        BitField("PN", 0b0, 1),
        BitEnumField("qualifier", 0b0000000, 7, FRQ_ENUM),
    ]


class SRQ(IOVal):
    name = "Section ready qualifier"
    fields_desc = [
        BitField("ready", 0b0, 1),
        BitEnumField("qualifier", 0b000000, 7, SRQ_ENUM),
    ]


class SCQ(IOVal):
    name = "Select and call qualifier"
    fields_desc = [
        BitEnumField("error", 0x0, 4, SCQ_ENUM_B),
        BitEnumField("qualifier", 0x0, 4, SCQ_ENUM_A),
    ]


class AFQ(IOVal):
    name = "Acknowledge file or section qualifier"
    fields_desc = [
        BitEnumField("error", 0x0, 4, AFQ_ENUM_B),
        BitEnumField("qualifier", 0x0, 4, AFQ_ENUM_A),
    ]


class IO(Packet):
    name = "Information object"
    __slots__ = ["sq", "number", "balanced"]

    def __init__(
        self,
        _pkt: bytes = b"",
        post_transform: Any = None,
        _internal: int = 0,
        _underlayer: Optional[Packet] = None,
        _parent: Optional[Packet] = None,
        sq: int = 0,
        **fields: Any,
    ) -> None:
        self.sq = sq
        self.number = len(_pkt) - 2 if sq == 1 else 1
        self.balanced: bool = (
            _parent.balanced
            if _parent is not None and "balanced" in _parent.__slots__
            else True
        )
        super().__init__(_pkt, post_transform, _internal, _underlayer, **fields)

    def extract_padding(self, s: bytes):
        return b"", s


class IO1(IO):
    name = "Single-point information without time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    FieldListField(
                        "SIQ",
                        [],
                        FlagsField("", 0x00, 8, SIQ_FLAGS),
                        length_from=lambda pkt: pkt.number,
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            FlagsField("SIQ", 0x00, 8, SIQ_FLAGS),
        ),
    ]


class IO2(IO):
    name = "Single-Point information with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("SIQ", 0x00, 8, SIQ_FLAGS),
        PacketField("time", CP24Time2a(b"\x00\x00\x00"), CP24Time2a),
    ]


class IO3(IO):
    name = "Double-point information without time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField("DIQ", [], DIQ, count_from=lambda pkt: pkt.number),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("DIQ", DIQ(b"\x03"), DIQ),
        ),
    ]


class IO4(IO):
    name = "Double-point information with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("DIQ", DIQ(b"\x03"), DIQ),
        PacketField("time", CP24Time2a(b"\x00\x00\x00"), CP24Time2a),
    ]


class IO5(IO):
    name = "Step position information"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "information",
                        [],
                        StepPosition,
                        count_from=lambda pkt: pkt.number,
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("information", StepPosition(b"\x00\x00"), StepPosition),
        ),
    ]


class IO6(IO):
    name = "Step position information with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        BitField("transient", 0b0, 1),
        BitField("value", 0b0000000, 7),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP24Time2a(b"\x00\x00\x00"), CP24Time2a),
    ]


class IO7(IO):
    name = "Bitstring of 32 bit"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "Bitstring", [], Bitstring32, count_from=lambda pkt: pkt.number
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("Bitstring", Bitstring32(), Bitstring32),
        ),
    ]


class IO8(IO):
    name = "Bitstring of 32 bit with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XBitField("BSI", 0x00, 32),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP24Time2a(b"\x00\x00\x00"), CP24Time2a),
    ]


class IO9(IO):
    name = "Measured value, normalized value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "value", [], NormalizedValue, count_from=lambda pkt: pkt.number
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("value", NormalizedValue(), NormalizedValue),
        ),
    ]


class IO10(IO):
    name = "Measured value, normalized value with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        NVA("NVA", 0.0),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO11(IO):
    name = "Measured value, scaled value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "value", [], ScaledValue, count_from=lambda pkt: pkt.number
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("value", ScaledValue(), ScaledValue),
        ),
    ]


class IO12(IO):
    name = "Measured value, scaled value with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LESignedShortField("SVA", 0x0000),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO13(IO):
    name = "Measured value, short floating point number"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "value", [], ShortFloat, count_from=lambda pkt: pkt.number
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("value", ShortFloat(), ShortFloat),
        ),
    ]


class IO14(IO):
    name = "Measured value, short floating point number with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEIEEEFloatField("value", 0.0),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO15(IO):
    name = "Integrated totals"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField("BCR", [], BCR, count_from=lambda pkt: pkt.number),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("BCR", BCR(), BCR),
        ),
    ]


class IO16(IO):
    name = "Integrated totals with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("BCR", BCR(), BCR),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO17(IO):
    name = "Event of protection equipment with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("flags", 0b00000, 5, SEP_FLAGS),
        BitField("reserved", 0b0, 1),
        BitEnumField("event_state", 0b01, 2, ES_ENUM),
        LEShortField("elapsed_time", 0x0000),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO18(IO):
    name = "Packed start events of protection equipment with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("SPE", 0x00, 8, SPE_FLAGS),
        FlagsField("QDP", 0x00, 8, QDP_FLAGS),
        LEShortField("relay_duration", 0x0000),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO19(IO):
    name = "Packed output circuit information of protection equipment with time tag"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("OCI", 0x00, 8, OCI_FLAGS),
        FlagsField("QDP", 0x00, 8, QDP_FLAGS),
        LEShortField("relay_time", 0x0000),
        PacketField("time", CP24Time2a(), CP24Time2a),
    ]


class IO20(IO):
    name = "Packed single-point information with status change detection"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "SCD", [], StatusChange, count_from=lambda pkt: pkt.number
                    ),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            PacketField("SCD", StatusChange(), StatusChange),
        ),
    ]


class IO21(IO):
    name = "Measured value, normalized value without quality descriptor"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        MultipleTypeField(
            [
                (
                    FieldListField("NVA", [], NVA, count_from=lambda pkt: pkt.number),
                    lambda pkt: pkt.sq == 1,
                ),
            ],
            NVA("NVA", 0x0000),
        ),
    ]


class IO30(IO):
    name = "Single-point information with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("SIQ", 0x00, 8, SIQ_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO31(IO):
    name = "Double-point information with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("DIQ", 0x00, DIQ),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO32(IO):
    name = "Step position information with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("VTI", 0x00, VTI),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO33(IO):
    name = "Bitstring of 32 bits with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("BSI", 0x00000000, Bitstring32),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO34(IO):
    name = "Measured value, normalized value with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        NVA("NVA", 0x0000),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO35(IO):
    name = "Measured value, scaled value with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LESignedShortField("SVA", 0x0000),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO36(IO):
    name = "Measured value, short floating point number with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEIEEEFloatField("value", 0.0),
        FlagsField("QDS", 0x00, 8, QDS_FLAGS),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO37(IO):
    name = "Integrated totals with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("BCR", 0x0000000000, BCR),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO38(IO):
    name = "Event of protection equipment with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("flags", 0b00000, 5, SEP_FLAGS),
        BitField("reserved", 0b0, 1),
        BitEnumField("event_state", 0b01, 2, ES_ENUM),
        LEShortField("elapsed_time", 0x0000),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO39(IO):
    name = "Packed start events of protection equipment with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("SPE", 0x00, 8, SPE_FLAGS),
        FlagsField("QDP", 0x00, 8, QDP_FLAGS),
        LEShortField("relay_duration", 0x0000),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO40(IO):
    name = "Packed output circuit information of protection equipment with time tag CP56Time2a"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        FlagsField("OCI", 0x00, 8, OCI_FLAGS),
        FlagsField("QDP", 0x00, 8, QDP_FLAGS),
        LEShortField("relay_time", 0x0000),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO45(IO):
    name = "Single Command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QU", 0b00000, 5),
        BitField("reserved", 0b0, 1),
        BitEnumField("SCS", 0, 1, SC_ENUM),
    ]


class IO46(IO):
    name = "Double Command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QU", 0b00000, 5),
        BitEnumField("DCS", 0b01, 2, DC_ENUM),
    ]


class IO47(IO):
    name = "Regulating step command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QU", 0b00000, 5),
        BitEnumField("RCS", 0b00, 2, RCS_ENUM),
    ]


class IO48(IO):
    name = "Set-point command, normalized value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        NVA("NVA", 0x0000),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QL", 0b0000000, 7),
    ]


class IO49(IO):
    name = "Set-point command, scaled value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LESignedShortField("SVA", 0x0000),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QL", 0b0000000, 7),
    ]


class IO50(IO):
    name = "Set-point command, short floating point number"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEIEEEFloatField("value", 0.0),
        BitEnumField("SE", 0b0, 1, SE_ENUM),
        BitField("QL", 0b0000000, 7),
    ]


class IO51(IO):
    name = "Bitstring of 32 bit"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XBitField("BSI", 0x00, 32),
    ]


class IO70(IO):
    name = "End of initialization"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        BitField("after_change", 0b0, 1),
        BitEnumField("COI", 0b0000000, 7, COI_ENUM),
    ]


class IO100(IO):
    name = "Interrogation command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XByteEnumField("QOI", 0x0000, QOI_ENUM),
    ]


class IO101(IO):
    name = "Counter interrogation command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("QCC", QCC(), QCC),
    ]


class IO102(IO):
    name = "Read command"
    fields_desc = [XLEShortField("IOA", 0x0000)]


class IO103(IO):
    name = "Clock synchronization command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketField("time", CP56Time2a(), CP56Time2a),
    ]


class IO104(IO):
    name = "Test command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XLEShortField("FBP", 0x55AA),
    ]


class IO105(IO):
    name = "Reset process command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XByteEnumField("QRP", 0x00, QRP_ENUM),
    ]


class IO106(IO):
    name = "Delay acquisition command"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("delay_ms", 0x0000),
    ]


class IO110(IO):
    name = "Parameter of measured values, normalized value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        NVA("NVA", 0.0),
        PacketField("QPM", QPM(), QPM),
    ]


class IO111(IO):
    name = "Parameter of measured values, scaled value"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LESignedShortField("SVA", 0x0000),
        PacketField("QPM", QPM(), QPM),
    ]


class IO112(IO):
    name = "Parameter of measured values, short floating point number"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEIEEEFloatField("value", 0.0),
        PacketField("QPM", QPM(), QPM),
    ]


class IO113(IO):
    name = "Parameter activation"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        XByteEnumField("QPA", 0x00, QPA_ENUM),
    ]


class IO120(IO):
    name = "File ready"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        LEThreeBytesField("LOF", 0x000000),
        PacketField("FRQ", FRQ(), FRQ),
    ]


class IO121(IO):
    name = "Section ready"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        ByteField("NOS", 0x00),
        LEThreeBytesField("LOF", 0x000000),
        PacketField("SRQ", SRQ(), SRQ),
    ]


class IO122(IO):
    name = "Call directory, select file, call file, call section"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        ByteField("NOS", 0x00),
        PacketField("SCQ", SCQ(), SCQ),
    ]


class IO123(IO):
    name = "Last section, last segment"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        ByteField("NOS", 0x00),
        XByteEnumField("LSQ", 0x00, LSQ_ENUM),
        XByteField("CHS", 0x00),
    ]


class IO124(IO):
    name = "ACK file, ACK section"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        ByteField("NOS", 0x00),
        PacketField("AFQ", AFQ(), AFQ),
    ]


class IO125(IO):
    name = "Segment"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        LEShortField("NOF", 0x0000),
        ByteField("NOS", 0x00),
        FieldLenField("LOS", 0x00, length_of="segment", fmt="B"),
        StrLenField("segment", b"", length_from=lambda pkt: pkt.LOS, max_length=255),
    ]


class IO126(IO):
    name = "Directory"
    fields_desc = [
        MultipleTypeField(
            [(LEX3BytesField("IOA", 0x000000), lambda pkt: not pkt.balanced)],
            XLEShortField("IOA", 0x0000),
        ),
        PacketListField("entries", [], IOFile, length_from=lambda pkt: pkt.number),
    ]


class ASDU(Packet):
    name = "ASDU"
    __slots__ = ["balanced"]
    fields_desc = [
        XByteEnumField("type", 0x00, TYPEID_ASDU),
        PacketLenField("VSQ", VSQ(), VSQ, length_from=lambda pkt: 1),
        FlagsField("COT_flags", 0x00, 2, CAUSE_OF_TX_FLAGS),
        BitEnumField("COT", 0x00, 6, CAUSE_OF_TX),
        XByteField("CommonAddress", 0x00),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO1(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x01,
                ),
                (
                    PacketField("IO", IO1(), lambda b: IO1(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x01,
                ),
                (
                    PacketListField(
                        "IO", [], IO2, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x02,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO3(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x03,
                ),
                (
                    PacketField("IO", IO3(), lambda b: IO3(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x03,
                ),
                (
                    PacketListField(
                        "IO", [], IO4, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x04,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO5(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x05,
                ),
                (
                    PacketField("IO", IO5(), lambda b: IO5(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x05,
                ),
                (
                    PacketListField(
                        "IO", [], IO6, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x06,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO7(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x07,
                ),
                (
                    PacketField("IO", IO7(), lambda b: IO7(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x07,
                ),
                (
                    PacketListField(
                        "IO", [], IO8, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x08,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO9(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x09,
                ),
                (
                    PacketField("IO", IO9(), lambda b: IO9(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x09,
                ),
                (
                    PacketListField(
                        "IO", [], IO10, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x0A,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO11(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x0B,
                ),
                (
                    PacketField("IO", IO11(), lambda b: IO11(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x0B,
                ),
                (
                    PacketListField(
                        "IO", [], IO12, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x0C,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO13(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x0D,
                ),
                (
                    PacketField("IO", IO13(), lambda b: IO13(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x0D,
                ),
                (
                    PacketListField(
                        "IO", [], IO14, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x0E,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO15(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x0F,
                ),
                (
                    PacketField("IO", IO15(), lambda b: IO15(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x0F,
                ),
                (
                    PacketListField(
                        "IO", [], IO16, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x10,
                ),
                (
                    PacketListField(
                        "IO", [], IO17, count_from=lambda pkt: pkt.VSQ.number
                    ),
                    lambda pkt: pkt.type == 0x11,
                ),
                (PacketField("IO", IO18(), IO18), lambda pkt: pkt.type == 0x12),
                (PacketField("IO", IO19(), IO19), lambda pkt: pkt.type == 0x13),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO20(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x14,
                ),
                (
                    PacketField("IO", IO20(), lambda b: IO20(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x14,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO21(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x15,
                ),
                (
                    PacketField("IO", IO21(), lambda b: IO21(b, sq=1)),
                    lambda pkt: pkt.VSQ.SQ == 1 and pkt.type == 0x15,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO30(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x1E,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO31(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x1F,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO32(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x20,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO33(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x21,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO34(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x22,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO35(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x23,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO36(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x24,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO37(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x25,
                ),
                (
                    PacketListField(
                        "IO",
                        [],
                        lambda b: IO38(b, sq=0),
                        count_from=lambda pkt: pkt.VSQ.number,
                    ),
                    lambda pkt: pkt.VSQ.SQ == 0 and pkt.type == 0x26,
                ),
                (PacketField("IO", IO39(), IO39), lambda pkt: pkt.type == 0x27),
                (PacketField("IO", IO40(), IO40), lambda pkt: pkt.type == 0x28),
                (PacketField("IO", IO45(), IO45), lambda pkt: pkt.type == 0x2D),
                (PacketField("IO", IO46(), IO46), lambda pkt: pkt.type == 0x2E),
                (PacketField("IO", IO47(), IO47), lambda pkt: pkt.type == 0x2F),
                (PacketField("IO", IO48(), IO48), lambda pkt: pkt.type == 0x30),
                (PacketField("IO", IO49(), IO49), lambda pkt: pkt.type == 0x31),
                (PacketField("IO", IO50(), IO50), lambda pkt: pkt.type == 0x32),
                (PacketField("IO", IO51(), IO51), lambda pkt: pkt.type == 0x33),
                (PacketField("IO", IO70(), IO70), lambda pkt: pkt.type == 0x46),
                (PacketField("IO", IO100(), IO100), lambda pkt: pkt.type == 0x64),
                (PacketField("IO", IO101(), IO101), lambda pkt: pkt.type == 0x65),
                (PacketField("IO", IO102(), IO102), lambda pkt: pkt.type == 0x66),
                (PacketField("IO", IO103(), IO103), lambda pkt: pkt.type == 0x67),
                (PacketField("IO", IO104(), IO104), lambda pkt: pkt.type == 0x68),
                (PacketField("IO", IO105(), IO105), lambda pkt: pkt.type == 0x69),
                (PacketField("IO", IO106(), IO106), lambda pkt: pkt.type == 0x6A),
                (PacketField("IO", IO110(), IO110), lambda pkt: pkt.type == 0x6E),
                (PacketField("IO", IO111(), IO111), lambda pkt: pkt.type == 0x6F),
                (PacketField("IO", IO112(), IO112), lambda pkt: pkt.type == 0x70),
                (PacketField("IO", IO113(), IO113), lambda pkt: pkt.type == 0x71),
                (PacketField("IO", IO120(), IO120), lambda pkt: pkt.type == 0x78),
                (PacketField("IO", IO121(), IO121), lambda pkt: pkt.type == 0x79),
                (PacketField("IO", IO122(), IO122), lambda pkt: pkt.type == 0x7A),
                (PacketField("IO", IO123(), IO123), lambda pkt: pkt.type == 0x7B),
                (PacketField("IO", IO124(), IO124), lambda pkt: pkt.type == 0x7C),
                (PacketField("IO", IO125(), IO125), lambda pkt: pkt.type == 0x7D),
                (PacketField("IO", IO126(), IO126), lambda pkt: pkt.type == 0x7E),
            ],
            XStrField("IO", b""),
        ),
    ]

    def __init__(
        self,
        _pkt: bytes = b"",
        post_transform: Any = None,
        _internal: int = 0,
        _underlayer: Optional[Packet] = None,
        _parent: Optional[Packet] = None,
        **fields: Any,
    ) -> None:
        self.balanced: bool = (
            _parent.balanced
            if _parent is not None and "balanced" in _parent.__slots__
            else True
        )
        super().__init__(_pkt, post_transform, _internal, _underlayer, **fields)


class FT12Fixed(Packet):
    name = "FT 1.2 Fixed length"
    fields_desc = [
        XByteField("start", 0x10),
        FlagsField("Control_Flags", 0x4, 4, CONTROL_FLAGS),
        BitEnumField("fcode", 0x9, 4, FUNCTION_CODES),
        XByteField("address", 0x00),
        XByteField("checksum", 0x00),
        XByteField("end", 0x16),
    ]


class FT12Variable(Packet):
    name = "FT 1.2 Variable Length"
    fields_desc = [
        XByteField("start", 0x68),
        ByteField("length_1", 0x09),
        ByteField("length_2", 0x09),
        XByteField("start2", 0x68),
        FlagsField("Control_Flags", 0x4, 4, CONTROL_FLAGS),
        BitEnumField("fcode", 0x9, 4, FUNCTION_CODES),
        XByteField("address", 0x00),
        PacketLenField(
            "LinkUserData",
            ASDU(),
            ASDU,
            length_from=lambda pkt: pkt.getfieldval("length_1") - 2,
        ),
        XByteField("checksum", 0x00),
        XByteField("end", 0x16),
    ]


class FT12Single(Packet):
    name = "FT 1.2 Single character data"
    fields_desc = [
        XByteEnumField("acknowledge", 0xE5, {0xE5: "positive", 0xA2: "negative"})
    ]


class FT12Frame(Packet):
    name = "FT 1.2 Frame"

    def guess_payload_class(self, payload: bytes):
        if payload[0] in [0xA2, 0xE5]:
            return FT12Single
        if payload[0] == 0x10:
            return FT12Fixed
        if payload[0] == 0x68:
            return FT12Variable
        return self.default_payload_class(payload)
