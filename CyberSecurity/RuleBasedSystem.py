import pandas as pd


def generateCleanData(file):  # Cleans Data
    df = pd.read_csv(file)
    df['No.'] = df['No.'] - 1
    line = df.loc[(df['Protocol'] == 'TCP') | (df['Protocol'] == 'ICMP') | (df['Protocol'] == 'UDP')]
    # line = df.query()
    del line['No.']
    line.to_csv('clean_data/cleanPacketData.csv', index=False)


def DetectAttack(file):
    packet_data = pd.read_csv(file)
    attack_type = ["TCP Dos Flood", "ICMP Dos Flood", "UDP Dos Flood", "Normal User"]
    attacks_tcp = ["TCP Out-Of-Order", "Redirect", "PSH", "FIN", "TCP Dup ACK", "TCP Retransmission", "TCP Keep-Alive",
                   "TCP ACKed unseen segement", "RST", "TCP Window Full", "TCP ZeroWindow"]
    attacks_icmp = ["Destination Unreachable", "Redirect", "Time exceeded", "Parameter problem", "Source quench"]
    attacks_udp = ["BAD UDP LENGTH", "DHCP D ISCOVER", "  Misc Attack  ", "UDP       ET RBN ", "DHCP LEASE QUERY", ]

    with open("ipaddress/ipaddresslist.csv", "w", newline="\n") as f:
        for index, row in packet_data.iterrows():
            source = row["Source"]
            destination = row["Destination"]
            message = row["Info"]
            if attacks_tcp[0] in row["Info"] or attacks_tcp[1] in row["Info"] or attacks_tcp[2] in row["Info"] or \
                            attacks_tcp[3] in row[
                        "Info"] or attacks_tcp[4] in row["Info"] or attacks_tcp[5] in row["Info"] or attacks_tcp[1] in \
                    row["Info"] or \
                            attacks_tcp[
                                6] in row["Info"] or attacks_tcp[7] in row["Info"] or attacks_tcp[8] in row["Info"] or \
                            attacks_tcp[
                                9] in row["Info"] or \
                            attacks_tcp[10] in row["Info"]:
                flag = attack_type[0]
            elif attacks_icmp[0] in row["Info"] or attacks_icmp[1] in row["Info"] or attacks_icmp[2] in row["Info"] or \
                            attacks_icmp[3] in row["Info"] or attacks_icmp[4]:
                flag = attack_type[1]
            elif attacks_udp[0] in row["Info"] or attacks_udp[1] in row["Info"] or attacks_udp[2] in row["Info"] or \
                            attacks_udp[3] in row["Info"] or attacks_udp[4]:
                flag = attack_type[2]
            else:
                flag = attack_type[3]
            info = str(source) + ", " + str(flag) + "\n"

            f.write(info)


while True:
    generateCleanData("raw_data/tcp")
    DetectAttack("clean_data/cleanPacketData.csv")
