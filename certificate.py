# -*- coding: utf-8
import pyshark, struct, OpenSSL
from constants import PRETTY_NAMES
from binascii import hexlify

endian = '>'
verbose = True


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


def make_data(pcap_name):
    global endian  # 获取PCAP文件存储时的的大小端规则
    with open(pcap_name, "rb") as pcap_file:
        magic = struct.unpack('I', pcap_file.read(4))[0] & 0xFFFFFFFF
        endian = ">" if magic == 0xa1b2c3d4 else "<"

    pcap_raw = pyshark.FileCapture(pcap_name, use_json=True, include_raw=True)
    pcap_pre = pyshark.FileCapture(pcap_name)
    streams = {}
    for i, (packet_raw, packet_pre) in enumerate(zip(pcap_raw, pcap_pre)):
        if packet_pre.highest_layer == 'TLS':
            tls_raw = packet_raw.tls_raw.value
            tls_raw = tls_raw[0] if type(tls_raw) == list else tls_raw
            tls = bytes.fromhex(tls_raw)
            client = f"{packet_pre.ip.src_host}:{packet_pre.tcp.srcport}"
            server = f"{packet_pre.ip.dst_host}:{packet_pre.tcp.dstport}"
            conn_c2s, conn_s2c = f"{client}-{server}", f"{server}-{client}"
            handshake_type = ""

            verbose_print(f"Packet [{i:>2d}]", end=" ")
            record_content_type = struct.unpack(endian + 'B', tls[:1])[0]
            verbose_print(pretty_name('tls_record', record_content_type), end="")

            if "handshake_type" in packet_pre.tls.field_names:
                handshake_type = pretty_name('handshake_type', int(packet_pre.tls.handshake_type))
                verbose_print(",", handshake_type, end="")
            if handshake_type == "client_hello":
                if conn_c2s in streams or conn_s2c in streams:
                    conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                    if "client_hello" in streams[conn_key]:
                        streams[conn_key].clear()
                else:
                    client_hello = {"data": tls}
                    if "handshake_extensions_server_name" in packet_pre.tls.field_names:
                        tmp = packet_pre.tls.handshake_extensions_server_name.binary_value
                        tmp_index = tls.find(tmp)
                        client_hello['sni'] = (tmp_index, tmp_index + len(tmp))
                        streams[conn_c2s] = {"client_hello": client_hello}
            elif handshake_type == "server_hello":
                if conn_c2s in streams or conn_s2c in streams:
                    conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                    if "client_hello" in streams[conn_key]:
                        streams[conn_key]["server_hello"] = {"data": tls}
            elif conn_c2s in streams or conn_s2c in streams:
                conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                if "client_hello" in streams[conn_key] and "server_hello" in streams[conn_key]:
                    if "other" not in streams[conn_key]:
                        streams[conn_key]["other"] = {"data": tls, 'type': ""}
                        if "handshake_type" in packet_pre.tls.field_names:
                            streams[conn_key]["other"]["type"] = pretty_name('handshake_type',
                                                                             int(packet_pre.tls.handshake_type))
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
                if 'type' in stream_body:
                    verbose_print(",", stream_body['type'], end="")
                verbose_print()
    for conn in to_delete:
        del streams[conn]
    pcap_raw.close()
    pcap_pre.close()
    return streams


def parse_certificate(data, offset=5):
    information = []

    data = data[offset:]

    handshake_type, data, offset = unpacker('B', data, offset)
    length_h, data, offset = unpacker('B', data, offset)
    length_l, data, offset = unpacker('H', data, offset)
    handshake_length = (length_h << 16) + length_l

    length_h, data, offset = unpacker('B', data, offset)
    length_l, data, offset = unpacker('H', data, offset)
    cer_chain_length = (length_h << 16) + length_l

    while data:

        length_h, data, offset = unpacker('B', data, offset)
        length_l, data, offset = unpacker('H', data, offset)
        certificate_length = (length_h << 16) + length_l

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, data[: certificate_length])
        subjects = cert.get_subject().get_components()
        for _, domain in subjects:
            domain_offset = offset + data[: certificate_length].find(domain)
            domain_offset = (domain_offset, domain_offset + len(domain))
            information.append(domain_offset)
        # domain = subjects[-1][-1]
        # if "." in domain.decode("utf-8"):
        #     domain_offset = offset + data[: certificate_length].find(domain)
        #     domain_offset = (domain_offset, domain_offset + len(domain))
        #     information.append(domain_offset)

        # 序列号是由CA分配给每个证书的整数。对于给定CA的颁发的每个证书，它必须是唯一的（即，颁发者名称和序列号标识唯一的证书）
        serial_number = cert.get_serial_number()
        serial_number = hex(serial_number)[2:]
        serial_number = bytes.fromhex('0' * (32 - len(serial_number)) + serial_number)

        serial_offset = offset + data[: certificate_length].find(serial_number)
        serial_offset = (serial_offset, serial_offset + len(serial_number))
        information.append(serial_offset)

        data = data[certificate_length:]
        offset += certificate_length
    return information


if __name__ == '__main__':
    streams = make_data("/Users/liushangyu/Desktop/zhihu_1.pcap")
    for conn, stream in streams.items():
        if stream['other']['type'] == 'certificate':
            information = parse_certificate(stream['other']['data'])
            for offset in information:
                info = stream['other']['data'][offset[0]: offset[1]]
                try:
                    info = '"' + info.decode("utf-8") + '"'
                except:
                    info = hexlify(info).decode('ascii')
                print(f"[{offset[0]:>4d}:{offset[1]:>4d}] {info}")
