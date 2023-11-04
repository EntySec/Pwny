TLV_FILE_CHUNK = 1024

TLV_STATUS_QUIT = 0
TLV_STATUS_SUCCESS = 1
TLV_STATUS_FAIL = 2
TLV_STATUS_WAIT = 3
TLV_STATUS_NOT_IMPLEMENTED = 4
TLV_STATUS_USAGE_ERROR = 5
TLV_STATUS_RW_ERROR = 6
TLV_STATUS_ENOENT = 7


def tlv_custom_tag(pool, base, call):
    return (pool + base * 1000) + call


def tlv_custom_type(parent, child):
    return parent + child


TLV_TYPE_CHAR = (1 << 16)
TLV_TYPE_SHORT = (1 << 17)
TLV_TYPE_INT = (1 << 18)
TLV_TYPE_LONG = (1 << 19)

TLV_TYPE_UCHAR = (1 << 20)
TLV_TYPE_USHORT = (1 << 21)
TLV_TYPE_UINT = (1 << 22)
TLV_TYPE_ULONG = (1 << 23)

TLV_TYPE_LONGLONG = (1 << 24)
TLV_TYPE_FLOAT = (1 << 25)
TLV_TYPE_DOUBLE = (1 << 26)
TLV_TYPE_STRING = (1 << 27)
TLV_TYPE_BYTES = (1 << 28)
TLV_TYPE_TLV = (1 << 29)

TLV_TYPE_TAG = tlv_custom_type(TLV_TYPE_INT, 1)
TLV_TYPE_STATUS = tlv_custom_type(TLV_TYPE_INT, 2)
TLV_TYPE_PID = tlv_custom_type(TLV_TYPE_INT, 3)

TLV_TYPE_NODE_ID = tlv_custom_type(TLV_TYPE_INT, 4)
TLV_TYPE_NODE_SRC_ADDR = tlv_custom_type(TLV_TYPE_INT, 5)
TLV_TYPE_NODE_SRC_PORT = tlv_custom_type(TLV_TYPE_INT, 6)
TLV_TYPE_NODE_DST_ADDR = tlv_custom_type(TLV_TYPE_INT, 7)
TLV_TYPE_NODE_DST_PORT = tlv_custom_type(TLV_TYPE_INT, 8)
TLV_TYPE_TAB_ID = tlv_custom_type(TLV_TYPE_INT, 9)
TLV_TYPE_COUNT = tlv_custom_type(TLV_TYPE_INT, 10)

TLV_TYPE_TAB = tlv_custom_type(TLV_TYPE_BYTES, 1)
TLV_TYPE_MIGRATE = tlv_custom_type(TLV_TYPE_BYTES, 2)
TLV_TYPE_FILE = tlv_custom_type(TLV_TYPE_BYTES, 3)

TLV_TYPE_UUID = tlv_custom_type(TLV_TYPE_STRING, 1)
TLV_TYPE_FILENAME = tlv_custom_type(TLV_TYPE_STRING, 2)
