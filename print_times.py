import dpkt, glob, os, time
from search_tls1v3 import search_tls1v3

latest_time = 1561448782.682407
latest_time_index = (0, 0)
location = "/home/zzy/2021known"
for i, folder in enumerate(glob.glob(location + "/*")):
    if os.path.exists(os.path.join(folder, "TCP")):
        folder = os.path.join(folder, "TCP")
    if os.path.exists(os.path.join(folder, "UDP")):
        continue
    for j, file in enumerate(glob.glob(folder + "/*")):
        with open(file, 'rb') as pcap_file:
            capture = dpkt.pcap.Reader(pcap_file)
            for ts, buff in capture:
                if int(ts) > latest_time:
                    # latest_time = int(ts)
                    latest_time_index = (i, j)
                    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)), latest_time_index)
                    search_tls1v3(file)
                    break
