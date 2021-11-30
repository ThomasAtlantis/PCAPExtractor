import pyshark, glob, struct, os, sys, tqdm
from constants import PRETTY_NAMES
from binascii import hexlify
import numpy as np

endian = '>'
verbose = False


def verbose_print(*args, **kwargs):
    global verbose
    if verbose: print(*args, **kwargs)


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


def parse_extensions(payload, offset):
    extensions = []
    extensions_len, payload, offset = unpacker('H', payload, offset)
    payload = payload[: extensions_len]
    while payload:
        extension = Extension(payload, offset)
        offset = extension.offset_end
        extensions.append(extension)
        payload = payload[extension.length + 4:]
    return extensions


def parse_extension(payload, type_name, offset):
    offset_beg = offset
    entries = []
    pretty_entries = []

    format_list_length, format_entry = {
        'elliptic_curves': 'HH',
        'ec_point_formats': 'HB',
        'compression_methods': 'BB',
        'heartbeat': 'BB',
        'next_protocol_negotiation': 'Hp',
        'cipher_suites': 'HH',
        'supported_groups': 'HH',
        'signature_algorithms': 'HH',
        'renegotiation_info': 'HB',
        'status_request': 'HH',
        'status_request_v2': 'HH'
    }.get(type_name, "HB")

    if type_name != "next_protocol_negotiation" and len(payload) > 1:  # contents are a list
        list_length, payload, offset = unpacker(format_list_length, payload, offset)
        if list_length: payload = payload[:list_length]
    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload, offset = unpacker('B', payload, offset)
    if type_name == 'padding':
        return payload, hexlify(payload), (offset_beg, offset)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload), (offset_beg, offset)

    offset_beg = offset
    while len(payload) > 0:
        if type_name == 'server_name':
            _type, payload, offset = unpacker('B', payload, offset)
            offset_beg = offset
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'

        entry, payload, offset = unpacker(format_entry, payload, offset)

        entries.append(entry)
        if type_name == 'signature_algorithms':
            pretty_entries.append('{0}-{1}'.format(
                pretty_name('signature_algorithms_hash', entry >> 8),
                pretty_name('signature_algorithms_signature', entry % 256)))
        else:
            if format_entry.lower() == 'p':
                pretty_entries.append(entry)
            else:
                pretty_entries.append(pretty_name(type_name, entry))
    return entries, pretty_entries, (offset_beg, offset)


class Extension(object):
    def __init__(self, payload, offset):
        self._type_id, payload, offset = unpacker('H', payload, offset)
        self.type_name = pretty_name('extension_type', self._type_id)
        self.length, payload, offset = unpacker('H', payload, offset)
        self.offset_beg = self.offset_end = offset
        self._data, self._pretty_data = None, None
        if self.length > 0:
            self._data, self._pretty_data, (self.offset_beg, self.offset_end) = parse_extension(payload[:self.length],
                                                                                                self.type_name, offset)

    def __str__(self):
        return f"{self.offset_beg}:{self.offset_end} {self.type_name}: {self._pretty_data}"


def make_data(pcap_name):
    global endian  # 获取PCAP文件存储时的的大小端规则
    with open(pcap_name, "rb") as pcap_file:
        magic = struct.unpack('I', pcap_file.read(4))[0] & 0xFFFFFFFF
        endian = ">" if magic == 0xa1b2c3d4 else "<"

    pcap_raw = pyshark.FileCapture(pcap_name, use_json=True, include_raw=True)
    pcap_pre = pyshark.FileCapture(pcap_name)
    streams = {}
    for i, (packet_raw, packet_pre) in enumerate(zip(pcap_raw, pcap_pre)):
        if packet_pre.highest_layer == 'SSL':
            ssl_raw = packet_raw.ssl_raw.value
            ssl_raw = ssl_raw[0] if type(ssl_raw) == list else ssl_raw
            ssl = bytes.fromhex(ssl_raw)
            client = f"{packet_pre.ip.src_host}:{packet_pre.tcp.srcport}"
            server = f"{packet_pre.ip.dst_host}:{packet_pre.tcp.dstport}"
            conn_c2s, conn_s2c = f"{client}-{server}", f"{server}-{client}"
            verbose_print(f"Packet [{i:>2d}]", end=" ")
            if "record_content_type" in packet_pre.ssl.field_names:
                verbose_print(pretty_name('tls_record', int(packet_pre.ssl.record_content_type)), end="")
            if "handshake_type" in packet_pre.ssl.field_names and int(packet_pre.ssl.handshake_type) in [1, 2]:
                handshake_type = pretty_name('handshake_type', int(packet_pre.ssl.handshake_type))
                if handshake_type == "client_hello":
                    if conn_c2s in streams or conn_s2c in streams:
                        conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                        if "client_hello" in streams[conn_key]:
                            streams[conn_key].clear()
                    else:
                        client_hello = {"data": ssl}
                        if "handshake_extensions_server_name" in packet_pre.ssl.field_names:
                            verbose_print(", SNI='%s'" % packet_pre.ssl.handshake_extensions_server_name, end="")
                            record_raw, record_ofs, record_len = packet_raw.ssl.record_raw[: 3]
                            comp_len_raw, comp_len_ofs, comp_len_len = packet_raw.ssl.record.handshake.comp_methods_length_raw[
                                                                       : 3]
                            handshake_raw, handshake_ofs, handshake_len = packet_raw.ssl.record.handshake_raw[: 3]
                            comp_len = unpacker('B', bytes.fromhex(comp_len_raw))[0]
                            start = int(comp_len_ofs) - int(handshake_ofs) + int(comp_len_len) + comp_len
                            extensions = parse_extensions(bytes.fromhex(handshake_raw)[start:], start)
                            for extension in extensions:
                                if extension.type_name == 'server_name':
                                    # verbose_print(f"###### {extension.offset_beg}:{extension.offset_end}")
                                    # sni = ssl[int(handshake_ofs) - int(record_ofs) + extension.offset_beg: int(
                                    #     handshake_ofs) - int(record_ofs) + extension.offset_end]
                                    # verbose_print(unpacker('P', sni))
                                    client_hello['sni'] = (
                                        int(handshake_ofs) - int(record_ofs) + extension.offset_beg + 2,
                                        int(handshake_ofs) - int(record_ofs) + extension.offset_end)
                                    break
                            streams[conn_c2s] = {"client_hello": client_hello}
                elif handshake_type == "server_hello":
                    if conn_c2s in streams or conn_s2c in streams:
                        conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                        if "client_hello" in streams[conn_key]:
                            streams[conn_key]["server_hello"] = {"data": ssl}
            elif conn_c2s in streams or conn_s2c in streams:
                conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                if "client_hello" in streams[conn_key] and "server_hello" in streams[conn_key]:
                    if "other" not in streams[conn_key]:
                        streams[conn_key]["other"] = {"data": ssl}
            verbose_print()
    to_delete = []
    for conn, stream in streams.items():
        if len(stream) < 3:
            to_delete.append(conn)
        else:
            verbose_print(f"Connection [{conn}]")
            for stream_type, stream_body in stream.items():
                verbose_print(f"\t{stream_type}: {len(stream_body['data'])}", end="")
                if 'sni' in stream_body:
                    verbose_print(",", stream_body['data'][stream_body['sni'][0]: stream_body['sni'][1]], end="")
                verbose_print()
    for conn in to_delete:
        del streams[conn]
    pcap_raw.close()
    pcap_pre.close()
    return streams


def crop_data(data: bytes, size=256):
    return data + b'0' * (size - len(data)) if len(data) < size else data[:size]


if __name__ == '__main__':
    # Test
    # for i in range(3):
    #     make_data(glob.glob("/home/zzy/2021known/youtube/*")[i])

    data_X_SNI, data_X, data_y = [], [], []
    application_list = glob.glob("/home/zzy/2021known/*")
    for app_id, application in enumerate(application_list[:10]):
        if os.path.exists(os.path.join(application, 'TCP')):
            application = os.path.join(application, 'TCP')
        features_SNI, features = [], []
        for pcap in tqdm.tqdm(glob.glob(application + "/*")):
            for conn, data in make_data(pcap).items():
                data_client_hello = data['client_hello']['data']

                features_SNI.append(np.array([
                    list(crop_data(data_client_hello)),
                    list(crop_data(data['server_hello']['data'])),
                    list(crop_data(data['other']['data']))
                ]))

                sni_beg, sni_end = data['client_hello']['sni']
                data_client_hello = data_client_hello[:sni_beg] + \
                    b'0' * (sni_end - sni_beg) + data_client_hello[sni_end:]

                features.append(np.array([
                    list(crop_data(data_client_hello)),
                    list(crop_data(data['server_hello']['data'])),
                    list(crop_data(data['other']['data']))
                ]))

        data_X_SNI.append(np.array(features_SNI))
        data_X.append(np.array(features))
        data_y.append(np.full(len(features), app_id))
        print(data_X[-1].shape, data_y[-1].shape)
    data_X, data_X_SNI, data_y = np.vstack(data_X), np.vstack(data_X_SNI), np.hstack(data_y)
    np.save(f'/home/lsy/workspace/traffic/data_sni_X.npy', data_X_SNI)
    np.save(f'/home/lsy/workspace/traffic/data_X.npy', data_X)
    np.save(f'/home/lsy/workspace/traffic/data_y.npy', data_y)
    np.save(f'/home/lsy/workspace/traffic/app_table.npy', np.array(application_list))
