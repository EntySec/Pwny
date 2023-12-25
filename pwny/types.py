TLV_FILE_CHUNK = 4096

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


def tlv_custom_pipe(pool, base, type):
    return (pool + base * 1000) + type


def tlv_custom_type(parent, base, child):
    return (parent * 1000 + base * 100) + child


TLV_TYPE_CHAR = 1
TLV_TYPE_SHORT = 2
TLV_TYPE_INT = 3
TLV_TYPE_LONG = 4

TLV_TYPE_UCHAR = 5
TLV_TYPE_USHORT = 6
TLV_TYPE_UINT = 7
TLV_TYPE_ULONG = 8

TLV_TYPE_LONGLONG = 9
TLV_TYPE_FLOAT = 10
TLV_TYPE_DOUBLE = 11
TLV_TYPE_STRING = 12
TLV_TYPE_BYTES = 13
TLV_TYPE_GROUP = 14

TLV_TYPE_TAG = tlv_custom_type(TLV_TYPE_INT, 0, 1)
TLV_TYPE_STATUS = tlv_custom_type(TLV_TYPE_INT, 0, 2)
TLV_TYPE_PID = tlv_custom_type(TLV_TYPE_INT, 0, 3)

TLV_TYPE_TAB_ID = tlv_custom_type(TLV_TYPE_INT, 0, 4)

TLV_TYPE_TAB = tlv_custom_type(TLV_TYPE_BYTES, 0, 1)
TLV_TYPE_MIGRATE = tlv_custom_type(TLV_TYPE_BYTES, 0, 2)

TLV_TYPE_UUID = tlv_custom_type(TLV_TYPE_STRING, 0, 1)
TLV_TYPE_FILENAME = tlv_custom_type(TLV_TYPE_STRING, 0, 2)
TLV_TYPE_PATH = tlv_custom_type(TLV_TYPE_STRING, 0, 3)
