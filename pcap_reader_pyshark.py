import pyshark

pcap = pyshark.FileCapture('/Users/liushangyu/Desktop/test.pcap', use_json=True, include_raw=True)

packet = pcap[3]
print(dir(packet.tcp))
