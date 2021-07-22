# -*- coding: utf-8 -*-
import subprocess
import re
import codecs
import time


class WiFiScanner():
    """iw-based Wi-Fi networks scanner"""
    def __init__(self, interface):
        self.interface = interface

    def scan(self, dump_only=False):
        '''Parsing iw scan results'''
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'Security type': 'Unknown',
                        'WPS': False,
                        'WPS state': False,
                        'WPS locked': False,
                        'Response type': False,
                        'UUID': '',
                        'Manufacturer': '',
                        'Model': '',
                        'Model number': '',
                        'Serial number': '',
                        'Primary device type': '',
                        'Device name': '',
                        'Config methods': []
                     }
                )
            networks[-1]['BSSID'] = result.group(1).upper()
            networks[-1]['Last seen'] = time.time()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsState(line, result, networks):
            networks[-1]['WPS state'] = int(result.group(1))

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_responseType(line, result, networks):
            networks[-1]['Response type'] = int(result.group(1))

        def handle_uuid(line, result, networks):
            d = result.group(1)
            networks[-1]['UUID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_manufacturer(line, result, networks):
            d = result.group(1)
            networks[-1]['Manufacturer'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_serialNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Serial number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_primaryDeviceType(line, result, networks):
            networks[-1]['Primary device type'] = result.group(1)

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_configMethods(line, result, networks):
            networks[-1]['Config methods'] = result.group(1).split(', ')

        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] Wi-Fi Protected Setup State: (\d)'): handle_wpsState,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Response Type: (\d)'): handle_responseType,
            re.compile(r' [*] UUID: (.*)'): handle_uuid,
            re.compile(r' [*] Manufacturer: (.*)'): handle_manufacturer,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Serial Number: (.*)'): handle_serialNumber,
            re.compile(r' [*] Primary Device Type: (.*)'): handle_primaryDeviceType,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName,
            re.compile(r' [*] Config methods: (.*)'): handle_configMethods
        }

        cmd = 'iw dev {} scan'.format(self.interface)
        if dump_only:
            cmd += ' dump'
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []

        for line in lines:
            if line.startswith('command failed:'):
                print(line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        if not networks:
            return False
        return networks


def handle_network(network: dict) -> int:
    key_labels = {
        "BSSID": "bssid",
        "ESSID": "essid",
        "Security type": "security",
        "WPS": "wps_version",
        "WPS state": "wps_state",
        "WPS locked": "wps_locked",
        "Response type": "response_type",
        "UUID": "uuid",
        "Manufacturer": "manufacturer",
        "Model": "model",
        "Model number": "model_number",
        "Serial number": "serial_number",
        "Primary device type": "primary_device_type",
        "Device name": "device_name",
        "Config methods": "config_methods",
        "Last seen": "last_seen"
    }

    if not network['BSSID'] or\
        not any((network['Manufacturer'], network['Model'], network['Model number'],
                network['Serial number'], network['Device name'])):
        return 0

    matching_fields = dict(filter(lambda x: (x[0] in key_labels) and (x[1] != ''), network.items()))
    keys = []
    values = []
    for key, value in matching_fields.items():
        keys.append(key_labels[key])
        if key == "Config methods":
            value = ", ".join(value)
        values.append(value)

    query_string = "INSERT INTO network ({}) VALUES ({}) ON CONFLICT(bssid) DO UPDATE SET {};".format(
            ','.join(keys),
            ','.join('?' * len(keys)),
            ','.join(f'{k}=?' for k in keys)
        )
    r = conn.execute(query_string, values * 2)
    return r.rowcount


if __name__ == '__main__':
    import argparse
    import sqlite3
    import time
    import atexit

    parser = argparse.ArgumentParser(
        description='WiGLE Wardriving application assistant (Android).'
        'This program uses iw for scanning Wi-Fi networks and obtaining info about '
        'vendor, model, serial number etc. (WSC) and writes it to the local database (SQLite)',
        epilog='Example: %(prog)s -i wlan0 -d 3')

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help='Name of the wireless interface for scanning'
        )
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['real', 'dump'],
        default='dump',
        help='Network scan mode: real — real scanning (requires superuser access), '
        'dump — dumping the results of previous scans (no root required, if SELinux is permissive). '
        'Default: %(default)s'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=1.5,
        help='Delay between scans (in seconds). Default: %(default)s'
        )
    parser.add_argument(
        '-f', '--db-file',
        type=str,
        default='networks.db',
        help='SQLite database for saving results. Default: %(default)s'
        )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Print less information to stdout'
    )

    args = parser.parse_args()
    conn = sqlite3.connect(args.db_file)

    def cleanup():
        conn.commit()
        conn.close()

    atexit.register(cleanup)

    conn.execute('''CREATE TABLE IF NOT EXISTS "network" (
    "bssid" TEXT NOT NULL UNIQUE,
    "essid" TEXT,
    "security"  TEXT,
    "wps_version"   TEXT,
    "wps_state" INTEGER,
    "wps_locked"    INTEGER DEFAULT 0,
    "response_type" INTEGER,
    "uuid"  TEXT,
    "manufacturer"  TEXT,
    "model" TEXT,
    "model_number"  TEXT,
    "serial_number" TEXT,
    "primary_device_type"   TEXT,
    "device_name"   TEXT,
    "config_methods"    TEXT,
    "last_seen" TIMESTAMP,
    PRIMARY KEY("bssid")
);''')

    scanner = WiFiScanner(args.interface)
    prev_empty = False

    try:
        while True:
            if args.mode == 'real':
                results = scanner.scan()
            else:
                results = scanner.scan(dump_only=True)
            if not results:
                if args.quiet:
                    if prev_empty == True:
                        print('.', end='', flush=True)
                    else:
                        print('[-] No results — rescanning', end='', flush=True)
                else:
                    print('[-] No results — rescanning')

                prev_empty = True
                continue
            else:
                if prev_empty == True:
                    print('')
                cnt = len(results)
                # Filtering non-WPS networks
                results = list(filter(lambda x: bool(x['WPS']), results))
                wps_cnt = len(results)
                print(f'[+] Found {cnt} networks, {wps_cnt} with WPS', end='')
                prev_empty = False

            c = 0   # Number of networks added to the database
            for network in results:
                rows_affected = handle_network(network)
                if rows_affected:
                    c += rows_affected
            conn.commit()
            print(f', {c} rows affected')

            time.sleep(args.delay)
    except KeyboardInterrupt:
        print('\nAborting…')
