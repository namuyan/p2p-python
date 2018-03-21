#!/user/env python3
# -*- coding: utf-8 -*-

import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import requests
from urllib.request import Request, urlopen
import xmltodict
import logging
import threading
import time
import random

"""
UPnPによるNAT超え
参考：http://d.hatena.ne.jp/yogit/20101006/1286380061
巷のライブラリ動かないぞ
rebased
"""

NAME_SERVER = '8.8.8.8'


class UpnpClient(threading.Thread):
    f_stop = False
    finish = False
    f_wait = False
    opens = set()
    OPEN_SPAN = 7200

    def __init__(self):
        super().__init__(name='UPnPC', daemon=True)

    def stop(self):
        self.f_stop = True
        while not self.finish:
            time.sleep(1)

    def run(self):
        try:
            control_url = self.cast_rooter_request()
            soap_url = self.get_soap_url(control_url)
            external_ip = self.soap_get_ip(soap_url)
            local_ip = self.get_localhost_ip()
        except Exception as e:
            logging.info("UPnPC don't work!" % e)
            self.finish = True
            return
        if external_ip == local_ip:
            logging.info("This client is on local environment!")
            self.finish = True
            return

        ports = set()
        while not self.f_stop:
            self.waiting(5)
            try:
                # Action close port
                for p_out, p_in, protocol in ports - self.opens:
                    self.soap_delete_mapping(soap_url, (p_in, protocol))
                    ports.remove((p_out, p_in, protocol))

                # Action open port
                for p_out, p_in, protocol in self.opens - ports:
                    self.soap_add_mapping(soap_url, (p_out, p_in, local_ip, protocol, self.OPEN_SPAN, "Hello"))
                    ports.add((p_out, p_in, protocol))

                # Wait affect mapping
                self.waiting(30)

                # Check opened port
                mapping = self.soap_get_mapping(soap_url)
                if len(mapping) == 0:
                    self.waiting(self.OPEN_SPAN)
                    continue
                for p_out, p_in, protocol in ports:
                    for m in mapping:
                        if int(m['NewInternalPort']) == p_in:
                            break
                    else:
                        # Find not opened port, so action open
                        self.soap_add_mapping(
                            soap_url, (p_out, p_in, local_ip, protocol, self.OPEN_SPAN, "Hello"))

            except Exception as e:
                logging.error(e)

        else:
            # Finish, Close all port
            for p_out, p_in, protocol in ports:
                self.soap_delete_mapping(soap_url, (p_in, protocol))
                self.waiting(5)
            logging.info("Close UPnPC")
            self.finish = True

    def add_open_port(self, out_in_protocol):
        assert len(out_in_protocol) == 3, "Need three args"
        logging.info("Open port %d=>%d %s" % out_in_protocol)
        if out_in_protocol not in self.opens:
            self.opens.add(out_in_protocol)
            self.f_wait = False

    def remove_open_port(self, out_in_protocol):
        assert len(out_in_protocol) == 3, "Need three args"
        logging.info("Close port %d=>%d %s" % out_in_protocol)
        if out_in_protocol in self.opens:
            self.opens.remove(out_in_protocol)
            self.f_wait = False

    def waiting(self, c):
        self.f_wait = True
        while not self.f_stop and self.f_wait and c > 0:
            time.sleep(1)
            c -= 1
        self.f_wait = False

    @staticmethod
    def get_localhost_ip():
        return [
            (s.connect((NAME_SERVER, 80)), s.getsockname()[0], s.close())
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        ][0][1]

    @staticmethod
    def get_global_ip():
        network_info_providers = [
            "http://api.ipify.org/", 'http://myip.dnsomatic.com', 'http://inet-ip.info/ip'
        ]
        random.shuffle(network_info_providers)
        for url in network_info_providers:
            try:
                return requests.get(url).text.lstrip().rstrip()
            except:
                continue
        else:
            raise Exception('cannot find global ip')

    @staticmethod
    def cast_rooter_request(host='239.255.255.250', port=1900):
        messages = [
            'M-SEARCH * HTTP/1.1',
            'MX: 3',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'ST: urn:schemas-upnp-org:service:WANIPConnection:1',
        ]
        message = '\r\n'.join(messages)
        message += '\r\n\r\n'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode('utf8'), (host, port))
        res = sock.recv(1024)
        sock.close()
        res_list = res.decode().replace("\r\n", "\n").split("\n")
        for e in res_list:
            if 'LOCATION: ' in e:
                return e[10:]

    @staticmethod
    def get_soap_url(request_url):
        xml_string = requests.get(url=request_url).text
        xml = ET.fromstring(xml_string)
        ns = {'ns': 'urn:schemas-upnp-org:device-1-0'}
        for child in xml.findall(".//ns:service", ns):
            if child.find('ns:serviceType', ns).text == 'urn:schemas-upnp-org:service:WANIPConnection:1':
                control_url = child.find('ns:controlURL', ns).text
                parse = urlparse(request_url)
                return "{0}://{1}/{2}".format(parse.scheme, parse.netloc, control_url)

    @staticmethod
    def soap_get_ip(soap_url):
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

    @staticmethod
    def soap_get_mapping(soap_url):
        i_d = 0
        ports = list()
        while True:
            s_o_a_p = '<?xml version="1.0"?>\r\n'
            s_o_a_p += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle' \
                       '="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
            s_o_a_p += '<s:Body>\r\n'
            s_o_a_p += '<m:GetGenericPortMappingEntry xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
            s_o_a_p += '<NewPortMappingIndex>' + str(i_d) + '</NewPortMappingIndex>\r\n'
            s_o_a_p += '</m:GetGenericPortMappingEntry>\r\n'
            s_o_a_p += '</s:Body>\r\n'
            s_o_a_p += '</s:Envelope>\r\n'

            req = Request(soap_url)
            req.add_header('Content-Type', 'text/xml; charset="utf-8"')
            req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#GetGenericPortMappingEntry"')
            req.data = s_o_a_p.encode('utf8')

            try:
                result = xmltodict.parse(urlopen(req).read().decode())
                ports.append(dict(result['s:Envelope']['s:Body']['u:GetGenericPortMappingEntryResponse']))
            except Exception as e:
                if '500' not in str(e):
                    logging.debug(e)
                break
            i_d += 1
        return ports

    @staticmethod
    def soap_add_mapping(soap_url, add_setting):
        assert len(add_setting) == 6, "Need 6 params"
        external_port, internal_port, internal_client, protocol, duration, description = add_setting
        """
        external_port: WAN側のポート番号
        internal_port: 転送先ホストのポート番号
        internal_client: 転送先ホストのIPアドレス
        protocol: 'TCP' or 'UDP'
        duration: 設定の有効期間(秒)。0のときは無期限
        description: 'test'
        """
        s_o_a_p = '<?xml version="1.0"?>\r\n'
        s_o_a_p += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle' \
                   '="http://schemas.xmlsoap.org/soap/encoding/">\r\n'
        s_o_a_p += '<s:Body>\r\n'
        s_o_a_p += '<m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
        s_o_a_p += '<NewRemoteHost></NewRemoteHost>\r\n'
        s_o_a_p += '<NewExternalPort>' + str(external_port) + '</NewExternalPort>\r\n'
        s_o_a_p += '<NewProtocol>' + protocol + '</NewProtocol>\r\n'
        s_o_a_p += '<NewInternalPort>' + str(internal_port) + '</NewInternalPort>\r\n'
        s_o_a_p += '<NewInternalClient>' + internal_client + '</NewInternalClient>\r\n'
        s_o_a_p += '<NewEnabled>1</NewEnabled>\r\n'
        s_o_a_p += '<NewPortMappingDescription>' + str(description) + '</NewPortMappingDescription>\r\n'
        s_o_a_p += '<NewLeaseDuration>' + str(duration) + '</NewLeaseDuration>\r\n'
        s_o_a_p += '</m:AddPortMapping>\r\n'
        s_o_a_p += '</s:Body>\r\n'
        s_o_a_p += '</s:Envelope>\r\n'

        req = Request(soap_url)
        req.add_header('Content-Type', 'text/xml; charset="utf-8"')
        req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#AddPortMapping"')
        req.data = s_o_a_p.encode('utf8')

        try:
            result = xmltodict.parse(urlopen(req).read().decode())
            logging.debug(result["s:Envelope"]["s:Body"]["u:AddPortMappingResponse"]["@xmlns:u"])
            return True
        except Exception as e:
            logging.error(e)
            return False

    @staticmethod
    def soap_delete_mapping(soap_url, delete_setting):
        external_port, protocol = delete_setting
        """
        external_port: WAN側のポート番号
        protocol: 'TCP' or 'UDP'
        """
        s_o_a_p = '<?xml version="1.0"?>\r\n'
        s_o_a_p += '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle=' \
                   '"http://schemas.xmlsoap.org/soap/encoding/">\r\n'
        s_o_a_p += '<s:Body>\r\n'
        s_o_a_p += '<m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1">\r\n'
        s_o_a_p += '<NewRemoteHost></NewRemoteHost>\r\n'
        s_o_a_p += '<NewExternalPort>' + str(external_port) + '</NewExternalPort>\r\n'
        s_o_a_p += '<NewProtocol>' + protocol + '</NewProtocol>\r\n'
        s_o_a_p += '</m:DeletePortMapping>\r\n'
        s_o_a_p += '</s:Body>\r\n'
        s_o_a_p += '</s:Envelope>\r\n'

        req = Request(soap_url)
        req.add_header('Content-Type', 'text/xml; charset="utf-8"')
        req.add_header('SOAPACTION', '"urn:schemas-upnp-org:service:WANPPPConnection:1#DeletePortMapping"')
        req.data = s_o_a_p.encode('utf8')

        try:
            result = xmltodict.parse(urlopen(req).read().decode())
            logging.debug(result["s:Envelope"]["s:Body"]["u:DeletePortMappingResponse"]["@xmlns:u"])
        except Exception as e:
            logging.error(e)
