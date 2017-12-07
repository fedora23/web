from flask import Flask, render_template, request, url_for, flash, redirect
from flask_googlemaps import GoogleMaps
from flask_googlemaps import Map
import pygeoip
import socket
import urllib.request
import os
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
import csv
import pandas as pd

external_ip = urllib.request.urlopen('http://ident.me').read().decode('utf8')
hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)

app = Flask(__name__)
app.config['GOOGLEMAPS_KEY'] = "AIzaSyAYkWl0-rLmFkMvROv2FGBUlVS4OR387yE"
app.secret_key = 'AIzaSyAYkWl0-rLmFkMvROv2FGBUlVS4OR387yE'
GoogleMaps(app, key="AIzaSyAYkWl0-rLmFkMvROv2FGBUlVS4OR387yE")


@app.route("/")
def home():
    # creating a map in the view
    go = pygeoip.GeoIP('GeoLiteCity.dat')
    record = go.record_by_addr(external_ip)
    lat = record['latitude']
    long = record['longitude']

    sndmap = Map(
        identifier="sndmap",
        lat=lat,
        lng=long,
        style="height:500px;width=300px;margin:0;",
        zoom=8,
        markers=[
            {
                'icon': 'http://maps.google.com/mapfiles/ms/icons/red-dot.png',
                'lat': lat,
                'lng': long,
                'infobox': "<b>Hello World</b>"
            },

        ]
    )

    return render_template('map.html', sndmap=sndmap)


UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'CyberSecurity/raw_data')  ## this is the folder on my machine
ALLOWED_EXTENSIONS = set(['txt', 'csv'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def get_data():
    type_of_packet = []

    with open('ipaddress/ipaddresslist.csv') as in_file:
        csv_reader = csv.reader(in_file)
        for row in csv_reader:
            type_of_packet.append(tuple(row))
    return type_of_packet


def ip_loc_record():
    data = get_data()
    loc = []
    print(data)
    for packet in data:
        error = None
        ip = packet[0]
        go = pygeoip.GeoIP('GeoLiteCity.dat')
        a = go.record_by_addr(ip)
        if a is not None:
            loc.append(a)
        else:
            error = u"This is a private ip address, the iplocation cannot be found on the map at this time"
            print(error)
            # return redirect(url_for('map'))

    return loc


def icon_descr():
    data = get_data()
    icons = []
    icon_name = []
    for packet in data:
        if packet[1] == 'Normal User':
            icon = "static/img/bluemap_marker.png"
            icons.append(icon)
            icon_name.append(packet[1])
        elif packet[1] == "TCP Dos Flood":
            icon = "static/img/redmap-marker-icon.png"
            icons.append(icon)
            icon_name.append(packet[1])
        elif packet[1] == "ICMP Dos Flood":
            icon = "static/img/greenmap_marker.png"
            icons.append(icon)
            icon_name.append(packet[1])
        elif packet[1] == "UDP Dos Flood":
            icon = "static/img/bluemap_marker.png"
            icons.append(icon)
            icon_name.append(packet[1])
    return icons


def generateCleanData(file):  # Cleans Data
    df = pd.read_csv(file)
    df['No.'] = df['No.'] - 1
    line = df.loc[(df['Protocol'] == 'TCP') | (df['Protocol'] == 'ICMP') | (df['Protocol'] == 'UDP')]
    # line = df.query()
    del line['No.']
    cleandata = 'CyberSecurity/clean_data/cleanPacketData.csv'
    line.to_csv(cleandata, index=False)
    return cleandata


def DetectAttack(file, generated_file):
    packet_data = pd.read_csv(file)
    attack_type = ["TCP Dos Flood", "ICMP Dos Flood", "UDP Dos Flood", "Normal User"]
    attacks_tcp = ["TCP Out-Of-Order", "Redirect", "PSH", "FIN", "TCP Dup ACK", "TCP Retransmission", "TCP Keep-Alive",
                   "TCP ACKed unseen segement", "RST", "TCP Window Full", "TCP ZeroWindow"]
    attacks_icmp = ["Destination Unreachable", "Redirect", "Time exceeded", "Parameter problem", "Source quench"]
    attacks_udp = ["BAD UDP LENGTH", "DHCP D ISCOVER", "  Misc Attack  ", "UDP       ET RBN ", "DHCP LEASE QUERY", ]
    processed_data_location = "ipaddress/" + generated_file
    with open(processed_data_location, mode="w", encoding="utf-8", newline="\n") as f:
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


@app.route('/', methods=['GET', 'POST'])
def map():
    if request.method == 'POST':
        doc = request.files['file']
        filename = secure_filename(doc.filename)
        doc.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # saves the file in the machinealgorithm folder
        file = generateCleanData('CyberSecurity/raw_data/' + filename)  # processes raw packet data and returns it's
        # stored location
        generated_file = "ipaddresslist.csv"
        file = DetectAttack(file, generated_file)  # detects attack and stores log in
        # <CyberSecurity/ipaddress/ipaddresslist.csv>
        data_status = file
        print(data_status)
    error = None
    ip_rec = None
    count = 1
    while ip_rec is None:
        ip_rec = ip_loc_record()
        count += 1
        if ip_rec == "This is a private ip address the iplocation cannot be found on the map at this time":
            go = pygeoip.GeoIP('GeoLiteCity.dat')
            record = go.record_by_addr(external_ip)
            lat = record['latitude']
            long = record['longitude']
            error = "Ip address", str(count), "is a private IP. Hence  the location cannot be found on the map at " \
                                              "this time "
            sndmap = Map(
                identifier="sndmap",
                lat=lat,
                lng=long,
                style="height:500px;width=300px;margin:0;",
                zoom=8,
                markers=[
                    {
                        'icon': 'http://maps.google.com/mapfiles/ms/icons/red-dot.png',
                        'lat': lat,
                        'lng': long,
                        'infobox': "My System"
                    },

                ]
            )
            return render_template('map.html', sndmap=sndmap, error=error)
        else:
            lat = []
            long = []
            country = []
            for record in ip_rec:
                lat.append(record['latitude'])

            for record in ip_rec:
                long.append(record['longitude'])

            for record in ip_rec:
                country.append(record['country_name'])

            location = list(zip(lat, long, country))

            sndmap = Map(
                identifier="sndmap",
                lat=lat,
                lng=long,
                markers=location,
                fit_markers_to_bounds=True,
                style=(
                    "height:100%;"
                    "width:100%;"
                    "top:0;"
                    "left:0;"
                    "position:absolute;"
                    "z-index:200;"
                ), )
            # zoom=4)
            return render_template('map.html', sndmap=sndmap)


if __name__ == "__main__":
    app.run(debug=True)
