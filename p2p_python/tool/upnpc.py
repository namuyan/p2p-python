from urllib.request import Request, urlopen
from urllib.parse import urlparse
from xml.etree import ElementTree
from collections import namedtuple
from logging import getLogger
from typing import Optional, List
import xmltodict
import requests
import socket
import random


log = getLogger(__name__)
NAME_SERVER = '8.8.8.8'
Mapping = namedtuple('Mapping', [
    'enabled',  # int: 1
    'external_port',  # int: 38008
    'external_client',  # str: '192.168.1.1'
    'internal_port',  # int: 38008
    'lease_duration',  # int: 0
    'description',  # str: 'Apple'
    'protocol',  # str: 'TCP'
    'remote_host',  # None
])

"""how to use example
request_url = cast_rooter_request()
soap_url = get_soap_url(request_url)
print(soap_get_mapping(soap_url))
internal_client = get_localhost_ip()
soap_add_mapping(soap_url, 5000, 5000, internal_client)
print(soap_get_mapping(soap_url))
soap_delete_mapping(soap_url, 5000)
"""


def check_and_open_port_by_upnp(external_port, internal_port, protocol):
    """open the router's port to enable external connection"""
    request_url = cast_rooter_request()
    if request_url is None:
        log.debug("node is not in local network protected by a router")
        return
    soap_url = get_soap_url(request_url)
    internal_client = get_localhost_ip()
    # check existence
    for mapping in soap_get_mapping(soap_url):
        if mapping.enabled == 1 and \
                mapping.external_port == external_port and \
                mapping.internal_port == internal_port and \
                mapping.protocol == protocol and \
                mapping.external_client == internal_client:
            return
    # open port
    soap_add_mapping(soap_url, external_port, internal_port, internal_client, protocol)
    log.info(f"open port by upnp {internal_port} -> {external_port}")


def cast_rooter_request(host='239.255.255.250', port=1900) -> Optional[str]:
    try:
        messages = [
            'M-SEARCH * HTTP/1.1',
            'MX: 3',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'ST: urn:schemas-upnp-org:service:WANIPConnection:1',
        ]
        message = '\r\n'.join(messages)
        message += '\r\n\r\n'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(message.encode('utf8'), (host, port))
            res = sock.recv(1024)
        res_list = res.decode().replace("\r\n", "\n").split("\n")
        for e in res_list:
            if 'LOCATION: ' in e:
                return e[10:]
    except socket.timeout:
        pass
    except Exception as e:
        log.debug(e, exc_info=True)
    return None


def get_soap_url(request_url) -> Optional[str]:
    """get soap url"""
    xml_string = requests.get(url=request_url).text
    xml = ElementTree.fromstring(xml_string)
    ns = {'ns': 'urn:schemas-upnp-org:device-1-0'}
    for child in xml.findall(".//ns:service", ns):
        if child.find('ns:serviceType', ns).text == 'urn:schemas-upnp-org:service:WANIPConnection:1':
            control_url = child.find('ns:controlURL', ns).text
            parse = urlparse(request_url)
            return "{0}://{1}/{2}".format(parse.scheme, parse.netloc, control_url)
    return None


def soap_get_mapping(soap_url) -> List[Mapping]:
    """get upnp mapping"""
    i_d = 0
    ports = list()
    while True:
        soap = '<?xml version="1.0"?>\r\n'
        soap += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle' \
                   '="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
        soap += '<s:Body>\r\n'
        soap += '<m:GetGenericPortMappingEntry xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
        soap += '<NewPortMappingIndex>' + str(i_d) + '</NewPortMappingIndex>\r\n'
        soap += '</m:GetGenericPortMappingEntry>\r\n'
        soap += '</s:Body>\r\n'
        soap += '</s:Envelope>\r\n'

        req = Request(soap_url)
        req.add_header('Content-Type', 'text/xml; charset="utf-8"')
        req.add_header('SOAPACTION',
                       '"urn:schemas-upnp-org:service:WANPPPConnection:1#GetGenericPortMappingEntry"')
        req.data = soap.encode('utf8')

        try:
            result = xmltodict.parse(urlopen(req).read().decode())
            data = dict(result['s:Envelope']['s:Body']['u:GetGenericPortMappingEntryResponse'])
            ports.append(Mapping(
                int(data['NewEnabled']),
                int(data['NewExternalPort']),
                data['NewInternalClient'],
                int(data['NewInternalPort']),
                int(data['NewLeaseDuration']),
                data['NewPortMappingDescription'],
                data['NewProtocol'],
                data['NewRemoteHost'],
            ))
        except Exception as e:
            if '500' not in str(e):
                log.debug(e)
            break
        i_d += 1
    return ports


def soap_add_mapping(soap_url, external_port, internal_port, internal_client,
                     protocol='TCP', duration=0, description='') -> Optional[Mapping]:
    """
    add to upnp mapping
    add_setting:
        external_port: WAN側のポート番号
        internal_port: 転送先ホストのポート番号
        internal_client: 転送先ホストのIPアドレス
        protocol: 'TCP' or 'UDP'
        duration: 設定の有効期間(秒)。0のときは無期限
        description: 'test'
    """
    soap = '<?xml version="1.0"?>\r\n'
    soap += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle' \
        '="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
    soap += '<s:Body>\r\n'
    soap += '<m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
    soap += '<NewRemoteHost></NewRemoteHost>\r\n'
    soap += '<NewExternalPort>' + str(external_port) + '</NewExternalPort>\r\n'
    soap += '<NewProtocol>' + protocol + '</NewProtocol>\r\n'
    soap += '<NewInternalPort>' + str(internal_port) + '</NewInternalPort>\r\n'
    soap += '<NewInternalClient>' + internal_client + '</NewInternalClient>\r\n'
    soap += '<NewEnabled>1</NewEnabled>\r\n'
    soap += '<NewPortMappingDescription>' + str(description) + '</NewPortMappingDescription>\r\n'
    soap += '<NewLeaseDuration>' + str(duration) + '</NewLeaseDuration>\r\n'
    soap += '</m:AddPortMapping>\r\n'
    soap += '</s:Body>\r\n'
    soap += '</s:Envelope>\r\n'

    req = Request(soap_url)
    req.add_header('Content-Type', 'text/xml; charset="utf-8"')
    req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#AddPortMapping"')
    req.data = soap.encode('utf8')

    try:
        result = xmltodict.parse(urlopen(req).read().decode())
        if "@xmlns:u" in result["s:Envelope"]["s:Body"]["u:AddPortMappingResponse"]:
            return Mapping(1, external_port, internal_client, internal_port, duration, description, protocol, None)
    except Exception as e:
        log.error(e)
    return None


def soap_delete_mapping(soap_url, external_port, protocol='TCP') -> bool:
    """
    delete from upnp mapping
    external_port: WAN側のポート番号
    protocol: 'TCP' or 'UDP'
    """
    soap = '<?xml version="1.0"?>\r\n'
    soap += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle=' \
               '"http://schemas.xmlsoap.org/soap/encoding/">\r\n'
    soap += '<s:Body>\r\n'
    soap += '<m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
    soap += '<NewRemoteHost></NewRemoteHost>\r\n'
    soap += '<NewExternalPort>' + str(external_port) + '</NewExternalPort>\r\n'
    soap += '<NewProtocol>' + protocol + '</NewProtocol>\r\n'
    soap += '</m:DeletePortMapping>\r\n'
    soap += '</s:Body>\r\n'
    soap += '</s:Envelope>\r\n'

    req = Request(soap_url)
    req.add_header('Content-Type', 'text/xml; charset="utf-8"')
    req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#DeletePortMapping"')
    req.data = soap.encode('utf8')

    try:
        result = xmltodict.parse(urlopen(req).read().decode())
        if "@xmlns:u" in result["s:Envelope"]["s:Body"]["u:DeletePortMappingResponse"]:
            return True
    except Exception as e:
        log.error(e)
    return False


def get_external_ip(soap_url) -> str:
    """get external ip address"""
    s_o_a_p = '<?xml version="1.0"?>\r\n'
    s_o_a_p += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle=' \
               '"http://schemas.xmlsoap.org/soap/encoding/">\r\n'
    s_o_a_p += '<s:Body>\r\n'
    s_o_a_p += '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
    s_o_a_p += '</u:GetExternalIPAddress>\r\n'
    s_o_a_p += '</s:Body>\r\n'
    s_o_a_p += '</s:Envelope>\r\n'

    req = Request(soap_url)
    req.add_header('Content-Type', 'text/xml; charset="utf-8"')
    req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#GetExternalIPAddress"')
    req.data = s_o_a_p.encode('utf8')
    result = xmltodict.parse(urlopen(req).read().decode())
    return result['s:Envelope']['s:Body']['u:GetExternalIPAddressResponse']['NewExternalIPAddress']


def get_localhost_ip():
    """get local ip address"""
    try:
        return [
            (s.connect((NAME_SERVER, 80)), s.getsockname()[0], s.close())
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        ][0][1]
    except Exception as e:
        return '127.0.0.1'


def get_global_ip():
    """get global ip address"""
    network_info_providers = [
        'http://api.ipify.org/',
        'http://myip.dnsomatic.com',
        'http://inet-ip.info/ip',
        'http://v4.ident.me/',
    ]
    random.shuffle(network_info_providers)
    for url in network_info_providers:
        try:
            return requests.get(url).text.lstrip().rstrip()
        except Exception as e:
            continue
    else:
        log.info('cannot find global ip')
        return ""


def get_global_ip_ipv6():
    """get global ipv6 address"""
    network_info_providers = [
        'http://v6.ipv6-test.com/api/myip.php',
        'http://v6.ident.me/',
    ]
    random.shuffle(network_info_providers)
    for url in network_info_providers:
        try:
            return requests.get(url).text.lstrip().rstrip()
        except Exception as e:
            continue
    else:
        log.info('cannot find global ipv6 ip')
        return ""


__all__ = [
    "NAME_SERVER",
    "Mapping",
    "check_and_open_port_by_upnp",
    "cast_rooter_request",
    "get_soap_url",
    "soap_get_mapping",
    "soap_add_mapping",
    "soap_delete_mapping",
    "get_external_ip",
    "get_localhost_ip",
    "get_global_ip",
    "get_global_ip_ipv6",
]
