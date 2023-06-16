from scapy.all import *
from scapy.layers.inet import TCP,UDP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from statistics import pstdev
from sklearn.preprocessing import LabelEncoder ,PowerTransformer
from sklearn.model_selection import train_test_split
import pandas as pd
from xgboost import XGBClassifier
from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import os
import joblib
import warnings
import logging

warnings.filterwarnings("ignore")
log = logging.getLogger(__name__)

class network_traffic:

    def __init__(self,pcap_path):
        def FinFlagDist (packets):
            ######## FinFlagDist :::::::::::::

            # Initialize counters for TCP packets with FIN flag set, total TCP packets, and total sent packets
            tcp_with_fin_flag = 0
            total_tcp_packets = 0
            total_sent_packets = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source, increment total_sent_packets counter
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    if TCP in pkt:
                        # If the packet is a TCP packet, increment total_tcp_packets counter
                        total_tcp_packets += 1
                        # If the FIN flag is set in the TCP packet, increment tcp_with_fin_flag counter
                        if pkt[TCP].flags & 0x01:
                            tcp_with_fin_flag += 1

            # Calculate FinFlagDist by multiplying (|Stcp|/|S|) by Sfin
            if total_sent_packets != 0:
                Stcp = total_tcp_packets
                S = total_sent_packets
                Sfin = tcp_with_fin_flag
                FinFlagDist = (Stcp / S) * Sfin
            else:
                FinFlagDist = 0.0
            return FinFlagDist
        def SynFlagDist (packets):
            # Initialize counters for TCP packets with SYN flag set, total TCP packets, and total sent packets
            tcp_with_syn_flag = 0
            total_tcp_packets = 0
            total_sent_packets = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source, increment total_sent_packets counter
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    if TCP in pkt:
                        # If the packet is a TCP packet, increment total_tcp_packets counter
                        total_tcp_packets += 1
                        # If the SYN flag is set in the TCP packet, increment tcp_with_syn_flag counter
                        if pkt[TCP].flags & 0x02:
                            tcp_with_syn_flag += 1

            # Calculate SynFlagDist by multiplying (|Stcp|/|S|) by Ssyn
            if total_sent_packets != 0:
                Stcp = total_tcp_packets
                S = total_sent_packets
                Ssyn = tcp_with_syn_flag
                SynFlagDist = (Stcp / S) * Ssyn
            else:
                SynFlagDist = 0.0

            return SynFlagDist
        def RstFlagDist (packets):
            # Initialize counters for TCP packets with RST flag set, total TCP packets, and total sent packets
            tcp_with_rst_flag = 0
            total_tcp_packets = 0
            total_sent_packets = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source, increment total_sent_packets counter
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    if TCP in pkt:
                        # If the packet is a TCP packet, increment total_tcp_packets counter
                        total_tcp_packets += 1
                        # If the RST flag is set in the TCP packet, increment tcp_with_rst_flag counter
                        if pkt[TCP].flags & 0x04:
                            tcp_with_rst_flag += 1

            # Calculate RstFlagDist by multiplying (|Stcp|/|S|) by Srst
            if total_sent_packets != 0:
                Stcp = total_tcp_packets
                S = total_sent_packets
                Srst = tcp_with_rst_flag
                RstFlagDist = (Stcp / S) * Srst
            else:
                RstFlagDist = 0.0

            return RstFlagDist
        def PshFlagDist(packets):
            ######## PshFlagDist :::::::::::::

            # Initialize counters for TCP packets with PSH flag set, total TCP packets, and total sent packets
            tcp_with_psh_flag = 0
            total_tcp_packets = 0
            total_sent_packets = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source, increment total_sent_packets counter
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    if TCP in pkt:
                        # If the packet is a TCP packet, increment total_tcp_packets counter
                        total_tcp_packets += 1
                        # If the PSH flag is set in the TCP packet, increment tcp_with_psh_flag counter
                        if pkt[TCP].flags & 0x08:
                            tcp_with_psh_flag += 1

            # Calculate PshFlagDist by multiplying (|Stcp|/|S|) by Spsh
            if total_sent_packets != 0:
                Stcp = total_tcp_packets
                S = total_sent_packets
                Spsh = tcp_with_psh_flag
                PshFlagDist = (Stcp / S) * Spsh
            else:
                PshFlagDist = 0.0

            return PshFlagDist
        def AckFlagDist(packets):
            ######## AckFlagDist :::::::::::::

            # Initialize counters for TCP packets with ACK flag set, total TCP packets, and total sent packets
            tcp_with_ack_flag = 0
            total_tcp_packets = 0
            total_sent_packets = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source, increment total_sent_packets counter
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    if TCP in pkt:
                        # If the packet is a TCP packet, increment total_tcp_packets counter
                        total_tcp_packets += 1
                        # If the ACK flag is set in the TCP packet, increment tcp_with_ack_flag counter
                        if pkt[TCP].flags & 0x10:
                            tcp_with_ack_flag += 1

            # Calculate AckFlagDist by multiplying (|Stcp|/|S|) by Sack
            if total_sent_packets != 0:
                Stcp = total_tcp_packets
                S = total_sent_packets
                Sack = tcp_with_ack_flag
                AckFlagDist = (Stcp / S) * Sack
            else:
                AckFlagDist = 0.0

            return AckFlagDist
        def DNSoverIP(packets):
            ######## DNSoverIP :::::::::::::

            # initialize counters
            total_sent_packets = 0
            dns_packets = 0

            # loop through each packet in the pcap file
            for pkt in packets:
                # increment total_packets counter for each packet
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    # if the packet is a DNS packet, increment dns_packets counter
                    if DNS in pkt:
                        dns_packets += 1

            # calculate DNS over IP ratio
            dns_over_ip_ratio = dns_packets / total_sent_packets

            return dns_over_ip_ratio
        def TCPoverIP(packets):
            # initialize counters
            total_ip_packets = 0
            tcp_packets = 0

            # loop through each packet in the pcap file
            for pkt in packets:
                # increment total_packets counter for each packet
                if IP in pkt:
                    total_ip_packets += 1
                    # if the packet is a TCP packet, increment tcp_packets counter
                    if TCP in pkt:
                        tcp_packets += 1

            # calculate TCP over IP ratio
            tcp_over_ip_ratio = tcp_packets / total_ip_packets

            return tcp_over_ip_ratio
        def UDPoverIP(packets):
            ######## UDPoverIP :::::::::::::

            # initialize counters
            total_sent_packets = 0
            udp_packets = 0

            # loop through each packet in the pcap file
            for pkt in packets:
                # increment total_packets counter for each packet
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_sent_packets += 1
                    # if the packet is a UDP packet, increment udp_packets counter
                    if UDP in pkt:
                        udp_packets += 1

            # calculate UDP over IP ratio
            udp_over_ip_ratio = udp_packets / total_sent_packets

            return udp_over_ip_ratio
        def MinLen(packets):
            # Initialize a list of packet lengths
            packet_lengths = []

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is received by the source, append its length to the list of packet lengths
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    packet_lengths.append(len(pkt))

            # Calculate the minimum length of the received packets
            min_len = min(packet_lengths)

            return min_len
        def MaxLen(packets):
            ######## MaxLen :::::::::::::

            # Initialize max_length variable and source IP address
            max_length = 0
            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source IP address, check its length and update max_length if necessary
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    pkt_len = len(pkt)
                    if pkt_len > max_length:
                        max_length = pkt_len

            return max_length
        def StdDevLen(packets):
            # Initialize a list of packet lengths
            packet_lengths = []

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is sent from the source, append its length to the list of packet lengths
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    packet_lengths.append(len(pkt))

            # Calculate the standard deviation of the packet lengths using the stdev function from the statistics module
            if len(packet_lengths) < 2:
                return float('nan')
            else:
                stddev_len = pstdev(packet_lengths)

            return stddev_len
        def AvgLen(packets):
            # Initialize total length and packet count variables
            total_len = 0
            pkt_count = 0

            # Iterate over packets
            for pkt in packets:
                # If the packet is sent from the source IP address, add its length to the total length and increment the packet count
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_len += len(pkt)
                    pkt_count += 1

            # Calculate the average length if there are packets sent from the source IP address, otherwise return 0
            if pkt_count > 0:
                avg_len = total_len / pkt_count
            else:
                avg_len = 0

            return avg_len
        def MinLenRx(packets):
            # Initialize a list of packet lengths
            packet_lengths = []

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is received by the source, append its length to the list of packet lengths
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    packet_lengths.append(len(pkt))

            # Calculate the minimum length of the received packets
            min_len_rx = min(packet_lengths)

            return min_len_rx
        def MaxLenRx(packets):
            # Initialize a list of packet lengths
            packet_lengths = []

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is received by the source, append its length to the list of packet lengths
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    packet_lengths.append(len(pkt))

            # Calculate the maximum length of the received packets
            max_len_rx = max(packet_lengths)

            return max_len_rx
        def StdDevLenRx(packets):
            # Initialize a list of packet lengths
            packet_lengths = []

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is received by the source, append its length to the list of packet lengths
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    packet_lengths.append(len(pkt))

            # Calculate the standard deviation of the packet lengths using the pstdev function from the statistics module
            if len(packet_lengths) < 2:
                return float('nan')
            else:
                stddev_len_rx = pstdev(packet_lengths)

            return stddev_len_rx
        def AvgLenRx(packets):
            # Initialize variables for packet count and total length
            pkt_count = 0
            total_len = 0

            # Loop through each packet in the list of packets
            for pkt in packets:
                # If the packet is received by the source, add its length to the total length and increment the packet count
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    total_len += len(pkt)
                    pkt_count += 1

            # Calculate the average length of the received packets
            avg_len_rx = total_len / pkt_count

            return avg_len_rx
        def FirstPktLen(packets):
            # Get the first packet in the list
            first_pkt = packets[0]

            # Calculate the length of the first packet
            first_pkt_len = len(first_pkt)

            return first_pkt_len
        def MinIAT(packets):
            # Initialize a list of inter-arrival times
            iats = []

            # Initialize the previous packet time to None
            prev_time = None

            # Iterate over packets and calculate inter-arrival time for each packet
            for pkt in packets:
                # If the packet is sent by the source, calculate the inter-arrival time
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    # If the previous packet time is not None, calculate the inter-arrival time
                    if prev_time:
                        iat = (pkt.time - prev_time)  # Convert to milliseconds
                        iats.append(iat)
                    # Set the previous packet time to the current packet time
                    prev_time = pkt.time


            # Calculate the minimum inter-arrival time
            if len(iats) < 2:
                min_iat = 0.0
            else:
                min_iat = min(iats)

            return min_iat
        def MaxIAT(packets):
            # Initialize a list of inter-arrival times
            iats = []

            # Initialize the previous packet time to None
            prev_time = None

            # Iterate over packets and calculate inter-arrival time for each packet
            for pkt in packets:
                # If the packet is sent by the source, calculate the inter-arrival time
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    # If the previous packet time is not None, calculate the inter-arrival time
                    if prev_time:
                        iat = (pkt.time - prev_time)  # Convert to milliseconds
                        iats.append(iat)
                    # Set the previous packet time to the current packet time
                    prev_time = pkt.time
            if len(iats) < 2:
                max_iat = 0.0
            else:
                # Calculate the maximum inter-arrival time
                max_iat = max(iats)

            return max_iat
        def AvgIAT(packets):
            # Initialize a list of inter-arrival times
            iats = []

            # Initialize the previous packet time to None
            prev_time = None

            # Iterate over packets and calculate inter-arrival time for each packet
            for pkt in packets:
                # If the packet is sent by the source, calculate the inter-arrival time
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    # If the previous packet time is not None, calculate the inter-arrival time
                    if prev_time:
                        iat = (pkt.time - prev_time)  # Convert to milliseconds
                        iats.append(iat)
                    # Set the previous packet time to the current packet time
                    prev_time = pkt.time

            if len(iats) < 2:
                avg_iat = 0.0
            else:
                # Calculate the average inter-arrival time
                avg_iat = sum(iats) / len(iats)

            return avg_iat
        def MinIATrx(packets):
            # Initialize a list of inter-arrival times for received packets
            iats_rx = []

            # Initialize the previous packet time to None
            prev_time_rx = None

            # Iterate over packets and calculate inter-arrival time for each received packet
            for pkt in packets:
                # If the packet is received by the destination, calculate the inter-arrival time
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    # If the previous received packet time is not None, calculate the inter-arrival time
                    if prev_time_rx:
                        iat_rx = (pkt.time - prev_time_rx) # Convert to milliseconds
                        iats_rx.append(iat_rx)
                    # Set the previous received packet time to the current packet time
                    prev_time_rx = pkt.time


            if len(iats_rx) < 2:
                min_iat_rx = 0.0
            else:
                # Calculate the minimum inter-arrival time for received packets
                min_iat_rx = min(iats_rx)
            return min_iat_rx
        def AvgIATrx(packets):
            # Initialize a list of inter-arrival times
            iats = []

            # Initialize the previous packet time to None
            prev_time = None

            # Iterate over packets and calculate inter-arrival time for each packet
            for pkt in packets:
                # If the packet is sent by the source, calculate the inter-arrival time
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    # If the previous packet time is not None, calculate the inter-arrival time
                    if prev_time:
                        iat = (pkt.time - prev_time)  # Convert to milliseconds
                        iats.append(iat)
                    # Set the previous packet time to the current packet time
                    prev_time = pkt.time
            if len(iats) < 2:
                avg_iat_rx = 0.0
            else:
                # Calculate the average inter-arrival time
                avg_iat_rx = sum(iats) / len(iats)

            return avg_iat_rx
        def count_HTTP_SH(packets):
            count = 0
            for pkt in packets:
                if TCP in pkt and pkt[IP].src == "192.168.56.101" and pkt.dport == 80:
                    # packet has the SYN flag set and is going to port 80 (HTTP)
                    count += 1
            return count
        def NumDstAddr(packets):
            # Initialize a list of unique destination IP addresses
            dst_addrs = []

            # Iterate over packets and add unique destination IP addresses to the list
            for pkt in packets:
                if IP in pkt:
                    dst_addr = pkt[IP].dst
                    if dst_addr not in dst_addrs:
                        dst_addrs.append(dst_addr)

            # Calculate the number of unique destination IP addresses
            num_dst_addrs = len(dst_addrs)

            return num_dst_addrs

        def FlowLEN(packets):
            # Initialize the total length of all packets sent by the source IP
            total_length = 0

            # Iterate over packets and add up the length of each packet sent by the source IP
            for pkt in packets:
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    total_length += len(pkt)

            return total_length
        def FlowLENrx(packets):
            # Initialize the total length of all packets sent by the source IP
            total_length = 0

            # Iterate over packets and add up the length of each packet sent by the source IP
            for pkt in packets:
                if IP in pkt and pkt[IP].dst == "192.168.56.101":
                    total_length += len(pkt)

            return total_length
        def DeltaTimeFlow(packets):
            # Initialize the start and end times to None
            start_time = None
            end_time = None
            count=0
            # Iterate over packets and find the start and end times
            for pkt in packets:
                if IP in pkt and pkt[IP].src == "192.168.56.101":
                    count=count+1
                    # If the start time is not set, set it to the time of the first packet
                    if start_time is None:
                        start_time = pkt.time
                    # If the end time is not set or the current packet time is greater than the end time, set it to the current packet time
                    elif end_time is None or pkt.time > end_time:
                        end_time = pkt.time

            # Calculate the DeltaTimeFlow
            if count==1 or count == 0:
                delta_time_flow=0.0
            else:
                delta_time_flow = end_time - start_time

            return delta_time_flow
        def StartFlow(packets):
            # Get the start time of the first packet
            StartFlow= packets[0].time
            return StartFlow
        def PktsIOratio(packets):
            # Initialize the start and end times to None
            count_s=0
            count_r = 0
            # Iterate over packets and find the start and end times
            for pkt in packets:
                if IP in pkt:

                    # If the start time is not set, set it to the time of the first packet
                    if pkt[IP].src == "192.168.56.101":
                        count_s=count_s+1
                    # If the end time is not set or the current packet time is greater than the end time, set it to the current packet time
                    elif pkt[IP].dst == "192.168.56.101":
                        count_r = count_r+1

            # Calculate the DeltaTimeFlow
            if count_s == 0 or count_r==0 :
                PktsIOratio=0.0
            else:
                PktsIOratio = count_s/count_r

            return PktsIOratio
        
        packets = rdpcap(pcap_path)

        self.FinFlagDist = FinFlagDist(packets)
        self.SynFlagDist = SynFlagDist(packets)
        self.RstFlagDist = RstFlagDist(packets)
        self.PshFlagDist = PshFlagDist(packets)
        self.AckFlagDist = AckFlagDist(packets)
        self.DNSoverIP = DNSoverIP(packets)
        self.TCPoverIP = TCPoverIP(packets)
        self.UDPoverIP = UDPoverIP(packets)
        self.MaxLen = MaxLen(packets)
        self.MinLen = MinLen(packets)
        self.StdDevLen = StdDevLen(packets)
        self.AvgLen = AvgLen(packets)
        self.MaxIAT = MaxIAT(packets)
        self.MinIAT = MinIAT(packets)
        self.AvgIAT = AvgIAT(packets)
        self.PktsIOratio = PktsIOratio(packets)
        self.FirstPktLen = FirstPktLen(packets)
        self.MaxLenrx = MaxLenRx(packets)
        self.MinLenrx = MinLenRx(packets)
        self.StdDevLenrx = StdDevLenRx(packets)
        self.AvgLenrx = AvgLenRx(packets)
        self.MinIATrx = MinIATrx(packets)
        self.AvgIATrx = AvgIATrx(packets)
        self.FlowLEN = FlowLEN(packets)
        self.FlowLENrx = FlowLENrx(packets)
        self.NumIPdst = NumDstAddr(packets)
        self.Start_flow = StartFlow(packets)
        self.DeltaTimeFlow = DeltaTimeFlow(packets)
        self.HTTPpkts = count_HTTP_SH(packets)

    def Build(self):
        item = {}
         # Loops over each attribute (attr) and its corresponding value (k) in the self object's dictionary (__dict__). The self object 
         # refers to an instance of the class in which the Build method is defined.
        for attr, k in self.__dict__.items():
            # Adds each attribute and its value to the item dictionary. Here, the line item[attr] = k assigns the value k to the key attr
            # in the item dictionary.
            item[attr] = k
        return item



def train_model():
    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/datasetnetworkala.csv"
    df = pd.read_csv(dataset_path)

    df.dropna(subset=['label'], inplace=True)
    df.loc[df['label'] == 0, 'label'] = "benign"
    df.loc[df['label'] == 1, 'label'] = "malware"
    threshold = df['label'].value_counts()
    df = df[df.isin(threshold.index[threshold >= 800]).values]
    features = df.columns[0:-1]
    X = df[features].values
    y = df.iloc[:, -1].values
    le = LabelEncoder()
    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)
    y = y_df.apply(le.fit_transform).values[:, :]
    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_)))
    target_names = list(encoded_labels.keys())


    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)
    y_train = y_train.ravel()

    xgb_clf = XGBClassifier(learning_rate= 0.2, 
                            max_depth = 3, 
                            min_child_weight = 1, 
                            subsample = 1)

    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features)

if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/traffic.joblib"):
    model, target_names, features = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/traffic.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/traffic.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/traffic.joblib")
else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/traffic.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/traffic.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/traffic.joblib")


class networkML(Processing):
    order = 4
    """Static analysis."""
    def run(self):
        """Run analysis.
        @return: results dict.
        """
        enabled = True
        
        self.key = "networkML"
        networkML = {}
        
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                return

            f = File(self.file_path)
            filename = os.path.basename(self.task["target"])
        else:
            return

        if filename:
            ext = filename.split(os.path.extsep)[-1].lower()
        else:
            ext = None

        package = self.task.get("package")


        if package == "exe" or ext == "exe" or "PE32" in f.get_type():
            try:
                net = network_traffic(self.pcap_path)
                sample = net.Build()
            except Exception as e:
                print(e)
                log.warning("we can't use net.Build() ")
                return None

            sample_df = pd.DataFrame([sample])

            sample_df.insert(loc=0, column="family", value="-1")

            X_sample = sample_df[features].values

            scaler = PowerTransformer()

            scaler.fit(X_sample)

            X_sample = scaler.transform(X_sample)

            predicted_list = model.predict_proba(X_sample)
            result = model.predict(X_sample)[0]
            confidence = round(predicted_list[0][result]*100, 2)

            if result == 0:
                family = target_names[result]
            else:
                family = target_names[result]

            proba= []

            for p,n in zip(predicted_list[0], target_names):
                proba.append("{} : {}".format(n, round(p, 2)))
            
            
            networkML = {
                "proba": proba,
                "family": family,
                "confidence":confidence
            }
                        
        return networkML

