import pyshark, glob, struct, os, sys, tqdm
from constants import PRETTY_NAMES
from binascii import hexlify
import numpy as np

endian = '>'

def pretty_name(name_type, name_value):
    result = PRETTY_NAMES.get(name_type, 'UType: {0}'.format(name_type))
    return result if ':' in result else result.get(
        name_value, '{0}: UValue {1}'.format(name_value, name_type))


def unpacker(fmt, packet, offset=0):
    global endian
    length = {'B': 1, 'H': 2}.get(fmt)
    if fmt in 'pP':
        length, packet, offset = unpacker({'P': 'H', 'p': 'B'}[fmt], packet, offset)
        fmt = f'{length}s'
    data = struct.unpack(endian + fmt, packet[:length])[0]
    return data, packet[length:], offset + length


def tls_version(payload):
    extensions_len, payload, _ = unpacker('H', payload)
    payload = payload[: extensions_len]
    while payload:
        extension = Extension(payload)
        payload = payload[extension.length + 4:]
        if extension.data: return extension.data
    return 0x303


class Extension(object):
    def __init__(self, payload):
        self.typeid, payload, _ = unpacker('H', payload)
        self.length, payload, _ = unpacker('H', payload)
        self.data = unpacker('H', payload)[0] if self.length > 0 and self.typeid == 43 else None


def search_tls1v3(pcap_name):
    global endian  # 获取PCAP文件存储时的的大小端规则
    with open(pcap_name, "rb") as pcap_file:
        magic = struct.unpack('I', pcap_file.read(4))[0] & 0xFFFFFFFF
        endian = ">" if magic == 0xa1b2c3d4 else "<"
    pcap_raw = pyshark.FileCapture(pcap_name, use_json=True, include_raw=True)
    pcap_pre = pyshark.FileCapture(pcap_name)
    streams = {}
    for i, (packet_raw, packet_pre) in enumerate(zip(pcap_raw, pcap_pre)):
        if packet_pre.highest_layer == 'SSL':
            if "handshake_type" in packet_pre.ssl.field_names and int(packet_pre.ssl.handshake_type) == 2:
                if "handshake_extensions_length" in packet_pre.ssl.field_names:
                    record = packet_raw.ssl.record
                    record = record[0] if type(record) == list else record
                    handshake = record.handshake
                    handshake = handshake[0] if type(handshake) == list else handshake
                    handshake_raw = handshake.extensions_length_raw
                    handshake_raw = handshake_raw[0] if type(handshake_raw[0]) == list else handshake_raw
                    ex_len_raw, ex_len_ofs, ex_len_len = handshake.extensions_length_raw[: 3]
                    handshake_raw, handshake_ofs, handshake_len = handshake_raw[: 3]
                    start = int(ex_len_ofs) - int(handshake_ofs)
                    if tls_version(bytes.fromhex(handshake_raw)[start:]) == 0x304:
                        print(pcap_name)
    pcap_raw.close()
    pcap_pre.close()
    return streams


if __name__ == '__main__':
    # Test
    location = "/home/zzy/2021known"
    # for folder in glob.glob(location + "/*")[11:]:
    folder = location + "/viber_encrypted"
    if os.path.exists(os.path.join(folder, "TCP")):
        folder = os.path.join(folder, "TCP")
    if os.path.exists(os.path.join(folder, "UDP")):
        sys.exit(0)
    for file in glob.glob(folder + "/*")[0:]:
        search_tls1v3(file)
