#!/usr/bin/env python3

# Do NOT change this file!

from binascii import hexlify as tohex
import contextlib
import dpkt
import fcntl
import pathlib
import re
import requests
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import time

from nose.tools import with_setup


TEST_DIR = pathlib.Path(__file__).parent
ROOT_DIR = TEST_DIR.parent
SERVER_PORT = 22263


def _test_sigint(command_str):
    pkill_code = subprocess.call(
        ['pkill', '-' + str(signal.SIGINT), '-f', command_str],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    time.sleep(1)
    pgrep_code = subprocess.call(['pgrep', '-f', command_str],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    assert pkill_code == 0 and pgrep_code == 1, \
        'ERROR: "{}" did not exit on SIGINT'.format(command_str)


def _split_dumpcap(dumpcap_file):
    ret = []
    dscan = dpkt.pcap.Reader(dumpcap_file)
    for timestamp, buf in dscan:
        eth = dpkt.ethernet.Ethernet(buf)
        ret.append(eth)
    return ret


def _split_sniffer(sniffer_file):
    sniffer_data = sniffer_file.read().strip()
    ret = []
    while sniffer_data:
        ethidx = sniffer_data[1:].find(b'ETHERNET:') + 1
        if ethidx == 0:
            ret.append(sniffer_data.strip())
            sniffer_data = ''
        else:
            ret.append(sniffer_data[:ethidx].strip())
            sniffer_data = sniffer_data[ethidx:]
    return ret


def _test_sniffer_helper(dumpcap_pkts, sniffer_pkts, custom_check=None):
    assert len(dumpcap_pkts) == len(sniffer_pkts), \
        'ERROR: received {} packets from sniffer (expected {})\n{}\n{}'.format(
            len(sniffer_pkts), len(dumpcap_pkts), str(sniffer_pkts), str(dumpcap_pkts))

    mac_re_part = br'(([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2}))'
    eth_re = re.compile(br''.join([
        br'ETHERNET:\s*',
        br'src\[(?P<src>', mac_re_part, br')\]\s*',
        br'dst\[(?P<dst>', mac_re_part, br')\]\s*',
    ]))
    ip_re_part = br'((\d{1,3}.){3}\d{1,3})'
    ip1_re = re.compile(br''.join([
        br'IP:\s*',
        br'src\[(?P<src>', ip_re_part, br')\]\s*',
        br'dst\[(?P<dst>', ip_re_part, br')\]\s*',
    ]))
    ip2_re = re.compile(br''.join([
        br'\s+',
        br'ip_hdr_len\[(?P<ip_hdr_len>\d+)\]\s*',
        br'ip_data_len\[(?P<ip_data_len>\d+)\]\s*',
        br'Protocol:\s*(?P<ip_protocol>\w+)\s*'
    ]))

    for i, (dp, sp) in enumerate(zip(dumpcap_pkts, sniffer_pkts)):
        sp_lines = sp.splitlines()
        assert len(sp_lines) >= 3, \
            'ERROR: sniffer logged too few lines for packet {}'.format(i)

        # Ethernet
        src_mac = ':'.join('{:02x}'.format(b) for b in dp.src).encode()
        dst_mac = ':'.join('{:02x}'.format(b) for b in dp.dst).encode()

        eth_match = eth_re.fullmatch(sp_lines[0])
        assert eth_match, \
            'ERROR: first log line must match regex: {}'.format(eth_re)
        assert src_mac == eth_match.group('src').lower() and \
               dst_mac == eth_match.group('dst').lower(), \
            'ERROR: incorrect Ethernet src/dst MAC addresses'

        # IP first line
        if not isinstance(dp.data, dpkt.ip.IP):
            continue
        src_ip = '.'.join(str(b) for b in dp.ip.src).encode()
        dst_ip = '.'.join(str(b) for b in dp.ip.src).encode()

        ip1_match = ip1_re.fullmatch(sp_lines[1])
        assert ip1_match, \
            'ERROR: second log line must match regex: {}'.format(ip1_re)
        assert src_ip == ip1_match.group('src') and \
               dst_ip == ip1_match.group('dst'), \
            'ERROR: incorrect src/dst IP addresses'

        # IP second line
        ip2_match = ip2_re.fullmatch(sp_lines[2])
        assert ip2_match, \
            'ERROR: third log line must match regex: {}'.format(ip2_re)
        assert str(dp.ip.hl * 4).encode() == ip2_match.group('ip_hdr_len'), \
            'ERROR: ip_hdr_len incorrect ({})'.format(
                ip2_match.group('ip_hdr_len'))
        assert str(dp.ip.len - dp.ip.hl * 4).encode() == \
               ip2_match.group('ip_data_len'), \
            'ERROR: ip_data_len incorrect ({})'.format(
                ip2_match.group('ip_data_len'))
        assert ('IP_' + type(dp.ip.data).__name__).encode() == \
                ip2_match.group('ip_protocol'), \
            'ERROR: IP protocol incorrect ({})'.format(
                ip2_match.group('ip_protocol'))

        if custom_check is not None:
            custom_check(dp, sp)


def _sniffer_icmp_custom_check(dp, sp):
    sp_lines = sp.splitlines()
    assert len(sp_lines) >= 4, \
        'ERROR: sniffer logged too few lines for ICMP packet {}'.format(i)

    icmp_re = re.compile(br''.join([
        br'ICMP:\s*',
        br'type\[(?P<type>\w+)\]\s*',
        br'(id\[(?P<id>\d+)\]\s*',
        br'seq\[(?P<seq>\d+)\]\s*)?',
    ]))
    icmp_match = icmp_re.fullmatch(sp_lines[3])
    assert icmp_match, \
        'ERROR: fourth log line must match regex: {}'.format(icmp_re)

    icmp_type = icmp_match.group('type')
    if dp.ip.icmp.type == dpkt.icmp.ICMP_ECHO:
        assert icmp_type == b'ICMP_ECHO', \
            'ERROR: ICMP protocol incorrect (should be ICMP_ECHO)'
    elif dp.ip.icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
        assert icmp_type == b'ICMP_ECHOREPLY', \
            'ERROR: ICMP protocol incorrect (should be ICMP_ECHOREPLY)'


def test_sniffer_icmp():
    with \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as sniffer_file, \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as dumpcap_file, \
            subprocess.Popen('./sniffer lo >> ' +
                                 shlex.quote(sniffer_file.name),
                             cwd=str(ROOT_DIR),
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as sniffer_proc, \
            subprocess.Popen(['dumpcap', '-w', dumpcap_file.name,
                              '-i', 'lo', '-P'],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL) as dumpcap_proc:
        num_pings = 2

        try:
            time.sleep(1)
            for _ in range(num_pings):
                subprocess.check_call(
                    ['ping', '-c', '1', 'localhost'],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                time.sleep(2)

        finally:
            time.sleep(1)
            dumpcap_proc.terminate()
            _test_sigint('sniffer lo')

        dumpcap_pkts = _split_dumpcap(dumpcap_file)
        sniffer_pkts = _split_sniffer(sniffer_file)

    assert len(dumpcap_pkts) == 2 * num_pings, \
        'ERROR: it seems the test environment is messed up ' \
        "(make sure you aren't doing anything silly, then contact TFs)"

    _test_sniffer_helper(dumpcap_pkts, sniffer_pkts,
                         custom_check=_sniffer_icmp_custom_check)


def _sniffer_tcp_custom_check(dp, sp):
    sp_lines = sp.splitlines()
    assert len(sp_lines) >= 6, \
        'ERROR: sniffer logged too few lines for TCP packet {}'.format(i)

    tcp1_re = re.compile(br''.join([
        br'TCP:\s*',
        br'src_port\[(?P<src>\d+)\]\s*',
        br'dst_port\[(?P<dst>\d+)\]\s*',
    ]))
    tcp2_re = re.compile(br''.join([
        br'\s+',
        br'seq_num\[(?P<seq>\d+)\]\s*',
        br'ack_num\[(?P<ack>\d+)\]\s*',
    ]))
    tcp3_re = re.compile(br''.join([
        br'\s+',
        br'tcp_hdr_len\[(?P<tcp_hdr_len>\d+)\]\s*',
        br'tcp_data_len\[(?P<tcp_data_len>\d+)\]\s*',
        br'flags:(?P<flags>.*)',
    ]))

    tcp1_match = tcp1_re.fullmatch(sp_lines[3])
    assert tcp1_match, \
        'ERROR: fourth log line must match regex: {}'.format(tcp1_re)
    assert dp.ip.tcp.sport == int(tcp1_match.group('src')) and \
           dp.ip.tcp.dport == int(tcp1_match.group('dst')), \
       'ERROR: incorrect TCP src/dst ports'

    tcp2_match = tcp2_re.fullmatch(sp_lines[4])
    assert tcp2_match, \
        'ERROR: fifth log line must match regex: {}'.format(tcp2_re)
    assert dp.ip.tcp.seq == int(tcp2_match.group('seq')), \
        'ERROR: incorrect TCP sequence number'
    expected_ack = 0
    if hasattr(dp.ip.tcp, 'ack'):
        expected_ack = dp.ip.tcp.ack
    assert expected_ack == int(tcp2_match.group('ack')), \
        'ERROR: incorrect TCP acknowledgement number'

    tcp3_match = tcp3_re.fullmatch(sp_lines[5])
    assert tcp3_match, \
        'ERROR: sixth log line much match regex: {}'.format(tcp3_re)
    assert dpkt.tcp.TCP.__hdr_len__ + len(dp.ip.tcp.opts) == \
            int(tcp3_match.group('tcp_hdr_len')), \
        'ERROR: incorrect TCP header length'
    assert len(dp.ip.tcp.data) == int(tcp3_match.group('tcp_data_len')), \
        'ERROR: incorrect TCP data length'
    flags = set(tcp3_match.group('flags').upper().strip().split())
    flagmap = [b'FIN', b'SYN', b'RST', b'PUSH', b'ACK', b'URG', b'ECE', b'CWR']
    expected_flags = set(f for i, f in enumerate(flagmap)
                         if ((dp.ip.tcp.flags >> i)) & 1)
    assert expected_flags == flags, 'ERROR: incorrect TCP flags'

    datalines = sp_lines[6:]
    assert all(len(l) <= 16 for l in datalines), \
        'ERROR: TCP data output must be wrapped 16-char!'
    assert b''.join(datalines) == b''.join(dp.ip.tcp.data.splitlines()), \
        'ERROR: incorrect TCP data'


def test_sniffer_tcp():
    with \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as sniffer_file, \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as dumpcap_file, \
            subprocess.Popen(['ncat', '-l', str(SERVER_PORT), '--keep-open',
                               '--exec', '/usr/bin/env true'],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as server_proc, \
            subprocess.Popen('./sniffer lo >> ' +
                                 shlex.quote(sniffer_file.name),
                             cwd=str(ROOT_DIR),
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as sniffer_proc, \
            subprocess.Popen(['dumpcap', '-w', dumpcap_file.name,
                              '-i', 'lo', '-P'],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL) as dumpcap_proc:
        try:
            time.sleep(1)
            sock = socket.create_connection(('localhost', SERVER_PORT))
            sock.send(b'Hello how are you doing?\nHow is the project going?')
            time.sleep(1)
            sock.send(b"I'm gonna send a really long message. Have fun!\n" * 2000)
            time.sleep(2)
            sock.close()

        finally:
            time.sleep(1)
            server_proc.terminate()
            dumpcap_proc.terminate()
            _test_sigint('sniffer lo')

        dumpcap_pkts = _split_dumpcap(dumpcap_file)
        sniffer_pkts = _split_sniffer(sniffer_file)

    _test_sniffer_helper(dumpcap_pkts, sniffer_pkts,
                         custom_check=_sniffer_tcp_custom_check)


def test_sniffer_udp():
    with \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as sniffer_file, \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as dumpcap_file, \
            subprocess.Popen(['ncat', '-l', str(SERVER_PORT),
                              '--keep-open', '-u',
                              '--exec', '/usr/bin/env true'],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as server_proc, \
            subprocess.Popen('./sniffer lo >> ' +
                                 shlex.quote(sniffer_file.name),
                             cwd=str(ROOT_DIR),
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as sniffer_proc, \
            subprocess.Popen(['dumpcap', '-w', dumpcap_file.name,
                              '-i', 'lo', '-P'],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL) as dumpcap_proc:
        try:
            time.sleep(1)
            sock = socket.socket(type=socket.SOCK_DGRAM)
            sock.sendto(b'Hello how are you doing?\nIs UDP better?',
                        ('localhost', SERVER_PORT))
            time.sleep(1)
            sock.close()

        finally:
            time.sleep(1)
            server_proc.terminate()
            dumpcap_proc.terminate()
            _test_sigint('sniffer lo')

        dumpcap_pkts = _split_dumpcap(dumpcap_file)
        sniffer_pkts = _split_sniffer(sniffer_file)

    _test_sniffer_helper(dumpcap_pkts, sniffer_pkts)


def test_rst_http():
    good = False

    with \
            tempfile.TemporaryDirectory() as host_dir, \
            subprocess.Popen(['python3', '-m', 'http.server',
                              str(SERVER_PORT)],
                             cwd=host_dir,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as server_proc, \
            subprocess.Popen(['./rst_http', str(SERVER_PORT), 'lo'],
                             cwd=str(ROOT_DIR),
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as rst_proc:
        try:
            filename = 'big.txt'
            with open(str(pathlib.Path(host_dir) / filename), 'wb') as outfile:
                block = b'a' * (2 ** 20)
                for _ in range(32):
                    outfile.write(block)
            time.sleep(4)

            url = 'http://localhost:{}/{}'.format(SERVER_PORT, filename)
            try:
                requests.get(url)
            except Exception as e:
                if 'reset by peer' in str(e):
                    good = True
                else:
                    raise

        finally:
            time.sleep(1)
            server_proc.terminate()
            _test_sigint('rst_http {} lo'.format(SERVER_PORT))

    assert good, 'ERROR: rst_http did not succeed'


def _get_default_ifname():
    return subprocess.check_output(
        "route | grep '^default' | grep -o '[^ ]*$'",
        shell=True).strip()


# From https://stackoverflow.com/questions/24196932/
def _get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def test_hijack_telnet():
    @contextlib.contextmanager
    def dummy_sleep(before=0, after=0):
        time.sleep(before)
        yield
        time.sleep(after)

    with \
            tempfile.NamedTemporaryFile(delete=True,
                                        buffering=0) as server_file , \
            subprocess.Popen('./telnet_server.py {} >> {}'.format(
                                  SERVER_PORT, shlex.quote(server_file.name)),
                             cwd=str(ROOT_DIR / 'telnet_server' ),
                             shell=True,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as server_proc, \
            subprocess.Popen(['./hijack_telnet',
                              'localhost', str(SERVER_PORT), 'lo'],
                             cwd=str(ROOT_DIR),
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as rst_proc, \
            dummy_sleep(before=1), \
            subprocess.Popen(['telnet', 'localhost', str(SERVER_PORT)],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                            ) as client_proc:
        try:
            time.sleep(1)
            _test_sigint(
                'hijack_telnet localhost {} lo'.format(SERVER_PORT))
            time.sleep(1)

            assert b'BOOM' in server_file.read(), \
                'ERROR: hijack_telnet did not succeed'

        finally:
            time.sleep(1)
            try:
                server_proc.terminate()
            except ProcessLookupError:
                pass
            try:
                client_proc.terminate()
            except ProcessLookupError:
                pass
            subprocess.call(
                ['pkill', '-9', '-f',
                 'telnet_server.py {}'.format(SERVER_PORT)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.call(
                ['pkill', '-9', '-f',
                 './hijack_telnet localhost {} lo'.format(SERVER_PORT)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
