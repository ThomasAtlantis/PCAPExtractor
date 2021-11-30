#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
from binascii import hexlify
import socket, struct, enum, dpkt, time
from constants import PRETTY_NAMES

need_more_parse = False
streams = {}
encrypted_streams = set()


class Extension(object):
    def __init__(self, payload):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = pretty_name('extension_type', self._type_id)
        self.length, payload = unpacker('H', payload)
        self._data, self._pretty_data = None, None
        if self.length > 0:
            self._data, self._pretty_data = parse_extension(payload[:self.length], self._type_name)

    def __str__(self):
        return '{0}: {1}'.format(self._type_name, self._pretty_data)


def verbose_print(*args):
    print("#", end="")
    print(args)


class ContentType(enum.Enum):
    change_cipher_spec = 20
    alert, handshake = 21, 22
    application_data = 23

    @classmethod
    def is_legal(cls, content_type):
        return content_type in (e.value for e in cls)


def analyze_packet(_timestamp, packet, nth):
    # extract ethernet header
    eth = dpkt.ethernet.Ethernet(packet)

    # extract IP header: ip <- eth.data; TCP header: tcp <- ip.data; TLS header: tls <- tcp.data
    if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP) and len(eth.data.data.data):
        ip, tcp, tls = eth.data, eth.data.data, eth.data.data.data
        if tcp.dport == 443 or tcp.sport == 443:
            while True:
                try:
                    dpkt.ssl.tls_multi_factory(tls)
                except dpkt.ssl.SSL3Exception:
                    tls = tls[1:]
                else:
                    if ContentType.is_legal(tls[0]) and tls[0] != ContentType.application_data:
                        parse_tls_records(ip, tls, nth, _timestamp)
                    break
        else:
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as exception:
                verbose_print(exception)
            else:
                print(request)


def parse_tls_records(ip: dpkt.ip.IP, stream, nth, _timestamp):
    global encrypted_streams
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        verbose_print('exception while parsing TLS records: {0}'.format(exception))
        return
    print(f"\n### Packet [{nth:>2d}] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_timestamp))}")
    if not records: print("No Packet Body")
    for i, record in enumerate(records):
        print(f"Record [{i}]")
        record_type = pretty_name('tls_record', record.type)
        if record_type == 'handshake':
            parse_tls_handshake(ip, record.data, record.length)
        elif record_type == 'change_cipher':
            client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
            server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
            print(f'-> ChangeCipher {client} -> {server}')
            encrypted_streams.update({f"{client}-{server}", f"{server}-{client}"})
        else:
            print(f"OtherType: {record_type}")


# dpkt.ssl.TLSHandshake does not recognize Certificate_status
class TLSHandshake:

    def __init__(self, data):
        self.type = struct.unpack('>B', data[:1])[0]
        length_h, length_l = struct.unpack('>BH', data[1: 4])
        self.length = (length_h << 16) + length_l
        self.data = data[4:]


def parse_tls_handshake(ip: dpkt.ip.IP, data, record_length):
    global streams, encrypted_streams
    handshake_type = ord(data[:1])
    client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    if f"{client}-{server}" in encrypted_streams:
        print('[#] Encrypted Handshake Message')
        return
    if handshake_type == 4:
        print('[#] New Session Ticket is not implemented yet')
        return

    total_len_consumed = 0
    while total_len_consumed < record_length:
        buffers = data[total_len_consumed:]
        handshake = TLSHandshake(buffers)
        total_len_consumed += handshake.length + 4
        print({
                  0: '<- Hello Request {0} <- {1}',
                  1: '-> ClientHello {0} -> {1}',
                  2: '<- ServerHello {1} <- {0}',
                  11: '<- Certificate {1} <- {0}',
                  12: '<- ServerKeyExchange {0} <- {1}',
                  13: '<- CertificateRequest {1} <- {0}',
                  14: '<- ServerHelloDone {1} <- {0}',
                  15: '-> CertificateVerify {0} -> {1}',
                  16: '-> ClientKeyExchange {0} -> {1}',
                  20: '-> Finished {0} -> {1}',
                  22: '<- CertificateStatus {0} <- {1}'
              }[handshake.type].format(client, server))
        conn_c2s, conn_s2c = f"{client}-{server}", f"{server}-{client}"
        if handshake.type == 1:
            if conn_c2s in streams or conn_s2c in streams:
                conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                if "ClientHello" in streams[conn_key]:
                    streams[conn_key].clear()
            else:
                streams[conn_c2s] = {"ClientHello": ip.data.data}
        elif handshake.type == 2:
            if conn_c2s in streams or conn_s2c in streams:
                conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                if "ClientHello" in streams[conn_key]:
                    streams[conn_key]["ServerHello"] = ip.data.data
        else:
            if conn_c2s in streams or conn_s2c in streams:
                conn_key = conn_c2s if conn_c2s in streams else conn_s2c
                if "ClientHello" in streams[conn_key] and "ServerHello" in streams[conn_key]:
                    if "Other" not in streams[conn_key]:
                        streams[conn_key]["Other"] = ip.data.data

        if handshake.type == 1 and need_more_parse:
            parse_client_hello(handshake)

        if handshake.type == 2 and need_more_parse:
            parse_server_hello(handshake.data)


def unpacker(fmt, packet):
    length = {'B': 1, 'H': 2}.get(fmt)
    if fmt in 'pP':
        length, packet = unpacker({'P': 'H', 'p': 'B'}[fmt], packet)
        fmt = f'{length}s'
    data = struct.unpack('>' + fmt, packet[:length])[0]
    return data, packet[length:]


def parse_server_hello(handshake):
    payload = handshake.data
    session_id, payload = unpacker('p', payload)
    cipher_suite, payload = unpacker('H', payload)
    # print('[*]   Cipher: {0}'.format(pretty_name('cipher_suites', cipher_suite)))
    compression, payload = unpacker('B', payload)
    # print('[*]   Compression: {0}'.format(pretty_name('compression_methods', compression)))
    extensions = parse_extensions(payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_client_hello(handshake):
    hello = handshake.data
    payload = hello.data

    session_id, payload = unpacker('p', payload)
    # length = struct.unpack('>B', payload[:1])[0]
    # session_id = struct.unpack(f'>{length}s', payload[1: 1 + length])[0]
    # payload = payload[1 + length:]

    length, payload = unpacker('H', payload)
    pretty_cipher_suites = [
        pretty_name('cipher_suites', struct.unpack('>H', payload[i * 2: (i + 1) * 2])[0]) for i in range(length // 2)]
    payload = payload[length:]
    # verbose_print('TLS Record Layer Length: {0}'.format(len(handshake)))
    # verbose_print('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    # verbose_print('Client Hello Length: {0}'.format(len(hello)))
    # verbose_print('Session ID: {0}'.format(hexlify(session_id)))
    # print('[*]   Ciphers: {0}'.format(pretty_cipher_suites))

    length = struct.unpack('>B', payload[:1])[0]
    compressions = struct.unpack(f'>{length}s', payload[1: 1 + length])[0]
    pretty_compressions = [pretty_name('compression_methods', compression) for compression in compressions]
    # print('[*]   Compression methods: {0}'.format(pretty_compressions))
    payload = payload[1 + length:]
    extensions = parse_extensions(payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_extensions(payload):
    extensions = []
    if payload:
        print('[*]   Extensions:')
        extensions_len, payload = unpacker('H', payload)
        consumed = 0
        while consumed < extensions_len:
            extension = Extension(payload)
            extensions.append(extension)
            consumed += extension.length + 4
            payload = payload[extension.length + 4:]
    return extensions


def parse_extension(payload, type_name):
    """
    Parses an extension based on the type_name.
    Returns an array of raw values as well as an array of prettified values.
    """
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    format_entry = 'B'
    list_length = 0
    if type_name == 'elliptic_curves':
        format_list_length = 'H'
        format_entry = 'H'
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'heartbeat':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'next_protocol_negotiation':
        format_entry = 'p'
    else:
        if len(payload) > 1:  # contents are a list
            list_length, payload = unpacker(format_list_length, payload)

    # verbose_print('type {0}, list type is {1}, number of entries is {2}'.
    #               format(type_name, format_list_length, list_length))

    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'renegotiation_info':
        format_entry = 'B'
    if list_length:
        payload = payload[:list_length]
    while (len(payload) > 0):
        if type_name == 'server_name':
            _type, payload = unpacker('B', payload)
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
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
    return entries, pretty_entries


def pretty_name(name_type, name_value):
    result = PRETTY_NAMES.get(name_type, 'UType: {0}'.format(name_type))
    return result if ':' in result else result.get(
        name_value, '{0}: UValue {1}'.format(name_value, name_type))


def read_file(filename):
    with open(filename, 'rb') as f:
        capture = dpkt.pcap.Reader(f)
        for i, (timestamp, packet) in enumerate(capture):
            # if i > 4: break
            analyze_packet(timestamp, packet, i)
        to_delete = []
        for conn, stream in streams.items():
            if len(stream) < 3:
                to_delete.append(conn)
            else:
                print(f"Connection [{conn}]")
                for stream_type, stream_body in stream.items():
                    print(f"\t{stream_type}: {len(stream_body)}")
        for conn in to_delete:
            del streams[conn]


if __name__ == "__main__":
    read_file("/Users/liushangyu/Desktop/test.pcap")
