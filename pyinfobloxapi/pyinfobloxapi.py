#
# Copyright 2014 "Igor Feoktistov" <ifeoktistov@yahoo.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re
import requests
import json


class InfobloxNotFoundException(Exception):
    pass


class InfobloxNoIPavailableException(Exception):
    pass


class InfobloxNoNetworkAvailableException(Exception):
    pass


class InfobloxGeneralException(Exception):
    pass


class InfobloxBadInputParameter(Exception):
    pass


class InfobloxArgumentMismatch(Exception):
    pass


class Infoblox(object):
    """ Implements the following subset of Infoblox IPAM API via REST API
        create_network
        delete_network
        create_networkcontainer
        delete_networkcontainer
        get_next_available_network
        create_host_record
        create_txt_record
        delete_txt_record
        delete_host_record
        add_host_alias
        delete_host_alias
        create_cname_record
        delete_cname_record
        update_cname_record
        create_dhcp_range
        delete_dhcp_range
        get_next_available_ip
        get_host
        get_host_by_ip
        get_ip_by_host
        get_host_by_regexp
        get_txt_by_regexp
        get_host_by_extattrs
        get_host_extattrs
        get_network
        get_network_by_ip
        get_network_by_extattrs
        get_network_extattrs
        update_network_extattrs
        delete_network_extattrs
        update_host_record
        get_cname
    """

    def __init__(self, ipaddr, user, password, wapi_version,
                 dns_view, network_view, verify_ssl=False):
        """ Class initialization method
        :param ipaddr: IBA IP address of management interface
        :param user: IBA user name
        :param password: IBA user password
        :param wapi_version: IBA WAPI version (example: 1.0)
        :param dns_view: IBA default view
        :param network_view: IBA default network view
        :param verify_ssl: IBA SSL certificate validation (example: False)
        """
        self.host = ipaddr
        self.user = user
        self.password = password
        self.wapi_version = wapi_version
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify_ssl = verify_ssl
        self._setup_session()
        self._setup_extract_record()

    def _setup_session(self):
        self.s = requests.Session()
        self.s.auth = (self.user, self.password)
        self.s.verify = self.verify_ssl

    def _construct_url(self, endpoint):
        if endpoint[0] != '/':
            endpoint = '/' + endpoint

        return 'https://' + self.host \
               + '/wapi/v' + self.wapi_version + endpoint

    def _setup_extract_record(self):
        self.re = re.compile("record:\w+\/[^:]+:([^\/]+)\/")

    def _extract_record(self, ref):
        try:
            return self.re.match(ref).group(1)
        except:
            return ''

    def get_next_available_ip(self, network):
        """ Implements IBA next_available_ip REST API call

        :returns: IP v4 address
        :param network: network in CIDR format
        """
        rest_url = self._construct_url('/network')
        params = {'network': network, 'network_view': self.network_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network found: " + network)

            net_ref = r_json[0]['_ref']
            rest_url = self._construct_url(net_ref)
            params = {'_function': 'next_available_ip', 'num': 1}
            r = self.s.post(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code == 200:
                ip_v4 = r_json['ips'][0]
                return ip_v4
            else:
                if 'text' in r_json:
                    if 'code' in r_json and \
                       r_json['code'] == 'Client.Ibap.Data':
                        raise InfobloxNoIPavailableException(r_json['text'])
                    else:
                        raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_host_record(self, address, fqdn, ttl=None):
        """ Implements IBA REST API call to create IBA host record
        :param address: IP v4 address or NET v4 address in CIDR format
                        to get next_available_ip from
        :param fqdn: hostname in FQDN
        :param ttl: if defined, will override the zone ttl
        """
        if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$", address):
            ipv4addr = 'func:nextavailableip:' + address
        elif re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", address):
                ipv4addr = address
        else:
            raise InfobloxBadInputParameter(
                'Expected IP or NET address in CIDR format')
        rest_url = self._construct_url('/record:host')
        if ttl is None:
            payload = {
                'ipv4addrs': [{
                    'configure_for_dhcp': False,
                    'ipv4addr': ipv4addr
                }],
                'name': fqdn,
                'view': self.dns_view
            }
        else:
            payload = {
                'ipv4addrs': [{
                    'configure_for_dhcp': False,
                    'ipv4addr': ipv4addr
                }],
                'use_ttl': True,
                'ttl': ttl,
                'name': fqdn,
                'view': self.dns_view
            }
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_txt_record(self, text, fqdn):
        """ Implements IBA REST API call to create IBA txt record
        :returns: IP v4 address assigned to the host
        :param text: free text to be added to the record
        :param fqdn: hostname in FQDN
        """
        rest_url = self._construct_url('/record:txt')
        payload = {'text': text, 'name': fqdn, 'view': self.dns_view}
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_host_record(self, fqdn, ip=None):
        """ Implements IBA REST API call to delete IBA host record
        :param fqdn: hostname in FQDN
        :param ip: IP address IN A
        """
        rest_url = self._construct_url('/record:host')
        params = {'name': fqdn, 'view': self.dns_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested host found: " + fqdn)

            host_ref = r_json[0]['_ref']
            if ip and r_json[0]['ipv4addrs'][0]['ipv4addr'] != str(ip):
                raise InfobloxArgumentMismatch(
                    'Mismatch IP address: expecting %s, %s given' %
                    (r_json[0]['ipv4addrs'][0]['ipv4addr'], str(ip)))
            if self._extract_record(host_ref) != fqdn:
                raise InfobloxGeneralException(
                    "Received unexpected host reference: " + host_ref)
            rest_url = self._construct_url(host_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_txt_record(self, fqdn):
        """ Implements IBA REST API call to delete IBA TXT record
        :param fqdn: hostname in FQDN
        """
        rest_url = self._construct_url('/record:txt')
        params = {'name': fqdn, 'view': self.dns_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()

            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested host found: " + fqdn)

            host_ref = r_json[0]['_ref']
            if self._extract_record(host_ref) != fqdn:
                raise InfobloxGeneralException(
                    "Received unexpected host reference: " + host_ref)

            rest_url = self._construct_url(host_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def add_host_alias(self, host_fqdn, alias_fqdn):
        """ Implements IBA REST API call to add an alias to IBA host record
        :param host_fqdn: host record name in FQDN
        :param alias_fqdn: host record name in FQDN
        """
        rest_url = self._construct_url('/record:host')
        params = {
            'name': host_fqdn,
            'view': self.dns_view,
            '_return_fields': 'name,aliases'
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()

            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested host found: " + host_fqdn)

            ref = r_json[0]['_ref']
            if self._extract_record(ref) != host_fqdn:
                raise InfobloxGeneralException(
                    "Received unexpected host reference: " + ref)

            if 'aliases' in r_json[0]:
                aliases = r_json[0]['aliases']
                aliases.append(alias_fqdn)
                payload = {'aliases': aliases}
            else:
                payload = {'aliases': [alias_fqdn]}
            rest_url = self._construct_url(ref)
            r = self.s.put(url=rest_url, data=json.dumps(payload))
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_host_alias(self, host_fqdn, alias_fqdn):
        """ Implements IBA REST API call to add an alias to IBA host record
        :param host_fqdn: host record name in FQDN
        :param alias_fqdn: host record name in FQDN
        """
        rest_url = self._construct_url('/record:host')
        params = {
            'name': host_fqdn,
            'view': self.dns_view,
            '_return_fields': 'name,aliases'
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()

            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested host found: " + host_fqdn)

            ref = r_json[0]['_ref']
            if self._extract_record(ref) != host_fqdn:
                raise InfobloxGeneralException(
                    "Received unexpected host reference: " + ref)

            if 'aliases' not in r_json[0]:
                raise InfobloxNotFoundException(
                    "No requested host alias found: " + alias_fqdn)

            aliases = r_json[0]['aliases']
            aliases.remove(alias_fqdn)
            payload = {'aliases': aliases}
            rest_url = self._construct_url(ref)
            r = self.s.put(url=rest_url,
                           data=json.dumps(payload))
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(
                        r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_cname_record(self, canonical, name, ttl=None):
        """ Implements IBA REST API call to create IBA cname record
        :param canonical: canonical name in FQDN format
        :param name: the name for a CNAME record in FQDN format
        :param ttl: if defined, will override the zone ttl
        """
        rest_url = self._construct_url('/record:cname')
        if ttl is None:
            payload = {
                'canonical': canonical,
                'name': name,
                'view': self.dns_view
            }
        else:
            payload = {
                'canonical': canonical,
                'name': name,
                'use_ttl': True,
                'ttl': ttl,
                'view': self.dns_view
            }
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_cname_record(self, fqdn, canonical=None):
        """ Implements IBA REST API call to delete IBA cname record
        :param fqdn: CNAME
        :param canonical: the record pointed to
        """
        rest_url = self._construct_url('/record:cname')
        params = {'name': fqdn, 'view': self.dns_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested cname record found: " + fqdn)

            if canonical and r_json[0]['canonical'] != canonical:
                raise InfobloxArgumentMismatch(
                    'Mismatch canonical IN CNAME: expecting %s, %s given' %
                    (r_json[0]['canonical'], canonical))

            cname_ref = r_json[0]['_ref']
            if self._extract_record(cname_ref) != fqdn:
                raise InfobloxArgumentMismatch(
                    "Received unexpected cname record reference: " + cname_ref)

            rest_url = self._construct_url(cname_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def update_cname_record(self, canonical, name, ttl=None):
        """ Implements IBA REST API call to update or repoint IBA cname record
        :param canonical: canonical name in FQDN format
        :param name: the name for the new CNAME record in FQDN format
        """
        rest_url = self._construct_url('/record:cname')
        payload = {'name': name}
        try:
            r = self.s.get(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            # RFC1912 - A CNAME can not coexist with any other data, we
            #           should expect utmost one entry
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "CNAME: " + name + " not found.")
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            cname_ref = r_json[0]['_ref']
            if ttl is None:
                payload = {"canonical": canonical}
            else:
                payload = {"canonical": canonical, "ttl": ttl}
            rest_url = self._construct_url(cname_ref)
            r = self.s.put(url=rest_url, data=json.dumps(payload))
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_dhcp_range(self, start_ip_v4, end_ip_v4):
        """ Implements IBA REST API call to add DHCP range for given
            start and end addresses
        :param start_ip_v4: IP v4 address
        :param end_ip_v4: IP v4 address
        """
        rest_url = self._construct_url('/range')
        payload = {'start_addr': start_ip_v4, 'end_addr': end_ip_v4}
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_dhcp_range(self, start_ip, end_ip):
        """ Implements IBA REST API call to delete DHCP range for given
            start and end addresses
        :param start_ip: IP v4 address
        :param end_ip: IP v4 address
        """
        rest_url = self._construct_url('/range')
        params = {
            'start_addr': start_ip,
            'end_addr': end_ip,
            'network_view': self.network_view
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()

            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested range found: %s-%s" % (start_ip, end_ip))

            range_ref = r_json[0]['_ref']
            rest_url = self._construct_url(range_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code == 200:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_host(self, fqdn, fields=None):
        """ Implements IBA REST API call to retrieve host record fields
        Returns hash table of fields with field name as a hash key
        :param fqdn: hostname in FQDN
        :param fields: comma-separated list of field names (optional)
        """

        rest_url = self._construct_url('/record:host')
        params = {'name': fqdn, 'view': self.dns_view}
        if fields:
            params['_return_fields'] = fields
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) > 0:
                return r_json[0]
            else:
                raise InfobloxNotFoundException("No hosts found: " + fqdn)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_host_by_regexp(self, fqdn):
        """ Implements IBA REST API call to retrieve host records by fqdn regexp filter
        Returns array of host names in FQDN matched to given regexp filter
        :param fqdn: hostname in FQDN or FQDN regexp filter
        """
        rest_url = self._construct_url('/record:host')
        rest_url += '?name~=' + fqdn + '&view=' + self.dns_view
        hosts = []
        try:
            r = self.s.get(url=rest_url)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No hosts found for regexp filter: " + fqdn)
            for host in r_json:
                hosts.append(host['name'])
            return hosts
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_txt_by_regexp(self, fqdn):
        """ Implements IBA REST API call to retrieve TXT records by fqdn
            regexp filter
        Returns dictonary of host names in FQDN matched to given regexp
        filter with the TXT value
        :param fqdn: hostname in FQDN or FQDN regexp filter
        """
        rest_url = self._construct_url('/record:txt')
        rest_url += '?name~=' + fqdn + '&view=' + self.dns_view
        hosts = {}
        try:
            r = self.s.get(url=rest_url)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No txt records found for regexp filter: " + fqdn)
            for host in r_json:
                hosts[host['name']] = host['text']
            return hosts
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_host_by_ip(self, ip_v4):
        """ Implements IBA REST API call to find hostname by IP address
        Returns array of host names in FQDN associated with given IP address
        :param ip_v4: IP v4 address
        """
        rest_url = self._construct_url('/ipv4address')
        params = {'ip_address': ip_v4, 'network_view': self.network_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException("No IP found: " + ip_v4)
            if len(r_json[0]['names']) > 0:
                return r_json[0]['names']
            else:
                raise InfobloxNotFoundException(
                    "No host records found for IP: " + ip_v4)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_ip_by_host(self, fqdn):
        """ Implements IBA REST API call to find IP addresses by hostname
        Returns array of IP v4 addresses associated with given hostname
        :param fqdn: hostname in FQDN
        """
        rest_url = self._construct_url('/record:host')
        params = {'name': fqdn, 'view': self.dns_view}
        ipv4addrs = []
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException("No hosts found: " + fqdn)
            if len(r_json[0]['ipv4addrs']) == 0:
                raise InfobloxNotFoundException(
                    "No host records found for FQDN: " + fqdn)
            for ipv4addr in r_json[0]['ipv4addrs']:
                ipv4addrs.append(ipv4addr['ipv4addr'])
            return ipv4addrs
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_host_extattrs(self, fqdn, attributes=None):
        """ Implements IBA REST API call to retrieve host extensible attributes
        Returns hash table of attributes with attribute name as a hash key
        :param fqdn: hostname in FQDN
        :param attributes: array of extensible attribute names (optional)
        """
        rest_url = self._construct_url('/record:host')
        params = {
            'name': fqdn,
            'view': self.dns_view,
            '_return_fields': 'name,extattrs'
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()

            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested host found: " + fqdn)
            r_extattrs = r_json[0]['extattrs']
            extattrs = {}
            if attributes:
                for attribute in attributes:
                    if attribute in r_extattrs:
                        extattrs[attribute] = r_extattrs[attribute]['value']
                    else:
                        raise InfobloxNotFoundException(
                            "No requested attribute found: " + attribute)
            else:
                for attribute in r_extattrs.keys():
                    extattrs[attribute] = r_extattrs[attribute]['value']
            return extattrs
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_network(self, network, fields=None):
        """ Implements IBA REST API call to retrieve network object fields
        Returns hash table of fields with field name as a hash key
        :param network: network in CIDR format
        :param fields: comma-separated list of field names
        (optional, returns network in CIDR format and netmask if not specified)
        """
        if not fields:
            fields = 'network,netmask'
        rest_url = self._construct_url('/network')
        params = {
            'network': network,
            'network_view': self.network_view,
            '_return_fields': fields
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network found: " + network)
            return r_json[0]
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_network_by_ip(self, ip_v4):
        """ Implements IBA REST API call to find network by IP address
            which belongs to this network
        Returns network in CIDR format
        :param ip_v4: IP v4 address
        """
        rest_url = self._construct_url('/ipv4address')
        params = {'ip_address': ip_v4, 'network_view': self.network_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException("No IP found: " + ip_v4)
            if 'network' in r_json[0]:
                return r_json[0]['network']
            else:
                raise InfobloxNotFoundException(
                    "No network found for IP: " + ip_v4)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_network_by_extattrs(self, attributes):
        """ Implements IBA REST API call to find a network by it's
            extensible attributes
        Returns array of networks in CIDR format
        :param attributes: comma-separated list of attrubutes name/value
                           pairs in the format:
            attr_name=attr_value - exact match for attribute value
            attr_name:=attr_value - case insensitive match for attribute value
            attr_name~=regular_expression - match attribute value by regex
            attr_name>=attr_value - search by number greater than value
            attr_name<=attr_value - search by number less than value
            attr_name!=attr_value - search by number not equal of value
        """
        rest_url = self._construct_url('/network')
        rest_url += '?*' + "&*".join(attributes.split(","))
        rest_url += '&network_view=' + self.network_view
        networks = []
        try:
            r = self.s.get(url=rest_url)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No networks found for extensible attributes: "
                    + attributes)
            for network in r_json:
                if 'network' in network:
                    networks.append(network['network'])
            return networks
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_host_by_extattrs(self, attributes):
        """ Implements IBA REST API call to find host by it's extensible
            attributes
        Returns array of hosts in FQDN
        :param attributes: comma-separated list of attrubutes name/value
                           pairs in the format:
            attr_name=attr_value - exact match for attribute value
            attr_name:=attr_value - case insensitive match for attribute value
            attr_name~=regular_expression - match attribute value by regex
            attr_name>=attr_value - search by number greater than value
            attr_name<=attr_value - search by number less than value
            attr_name!=attr_value - search by number not equal of value
        """
        rest_url = self._construct_url('/record:host')
        rest_url += '?*' + "&*".join(attributes.split(","))
        rest_url += '&view=' + self.dns_view
        hosts = []
        try:
            r = self.s.get(url=rest_url)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No hosts found for extensible attributes: " + attributes)
            for host in r_json:
                if 'name' in host:
                    hosts.append(host['name'])
            return hosts
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_network_extattrs(self, network, attributes=None):
        """ Implements IBA REST API call to retrieve network extensible attributes
        Returns hash table of attributes with attribute name as a hash key
        :param network: network in CIDR format
        :param attributes: array of extensible attribute names (optional)
        """
        rest_url = self._construct_url('/network')
        params = {
            'network': network,
            'network_view': self.network_view,
            '_return_fields': 'network,extattrs'
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network found: " + network)
            r_extattrs = r_json[0]['extattrs']
            extattrs = {}
            if attributes:
                for attribute in attributes:
                    if attribute in r_extattrs:
                        extattrs[attribute] = r_extattrs[attribute]['value']
                    else:
                        raise InfobloxNotFoundException(
                            "No requested attribute found: " + attribute)
            else:
                for attribute in r_extattrs.keys():
                    extattrs[attribute] = r_extattrs[attribute]['value']
            return extattrs
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def update_network_extattrs(self, network, attributes):
        """ Implements IBA REST API call to add or update network
            extensible attributes
        :param network: network in CIDR format
        :param attributes: hash table of extensible attributes with
                           attribute name as a hash key
        """
        rest_url = self._construct_url('/network')
        params = {
            'network': network,
            'network_view': self.network_view,
            '_return_fields': 'network,extattrs'
        }
        extattrs = {}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network found: " + network)
            network_ref = r_json[0]['_ref']
            extattrs = r_json[0]['extattrs']
            for attr_name, attr_value in attributes.iteritems():
                extattrs[attr_name]['value'] = attr_value
            payload = {'extattrs': extattrs}
            rest_url = self._construct_url(network_ref)
            r = self.s.put(url=rest_url, data=json.dumps(payload))
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_network_extattrs(self, network, attributes):
        """ Implements IBA REST API call to delete network extensible attributes
        :param network: network in CIDR format
        :param attributes: array of extensible attribute names
        """
        rest_url = self._construct_url('/network')
        params = {
            'network': network,
            'network_view': self.network_view,
            '_return_fields': 'network,extattrs'
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network found: " + network)
            network_ref = r_json[0]['_ref']
            extattrs = r_json[0]['extattrs']
            for attribute in attributes:
                if attribute in extattrs:
                    del extattrs[attribute]
            payload = {'extattrs': extattrs}
            rest_url = self._construct_url(network_ref)
            r = self.s.put(url=rest_url, data=json.dumps(payload))
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_network(self, network):
        """ Implements IBA REST API call to create DHCP network object
        :param network: network in CIDR format
        """
        rest_url = self._construct_url('/network')
        payload = {'network': network, 'network_view': self.network_view}
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code not in (200, 201):
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_network(self, network):
        """ Implements IBA REST API call to delete DHCP network object
        :param network: network in CIDR format
        """
        rest_url = self._construct_url('/network')
        params = {'network': network, 'network_view': self.network_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException("No network found: " + network)
            network_ref = r_json[0]['_ref']
            rest_url = self._construct_url(network_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code == 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def create_networkcontainer(self, networkcontainer):
        """ Implements IBA REST API call to create DHCP network containert object
        :param networkcontainer: network container in CIDR format
        """
        rest_url = self._construct_url('/networkcontainer')
        payload = {
            'network': networkcontainer,
            'network_view': self.network_view
        }
        try:
            r = self.s.post(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code not in (200, 201):
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def delete_networkcontainer(self, networkcontainer):
        """ Implements IBA REST API call to delete DHCP network container object
        :param networkcontainer: network container in CIDR format
        """
        rest_url = self._construct_url('/networkcontainer')
        params = {
            'network': networkcontainer,
            'network_view': self.network_view
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No network container found: " + networkcontainer)
            network_ref = r_json[0]['_ref']
            rest_url = self._construct_url(network_ref)
            r = self.s.delete(url=rest_url)
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_next_available_network(self, networkcontainer, cidr):
        """ Implements IBA REST API call to retrieve next available
            network of network container
        Returns network address in CIDR format
        :param networkcontainer: network container address in CIDR format
        :param cidr: requested network length (from 0 to 32)
        """
        rest_url = self._construct_url('/networkcontainer')
        params = {
            'network': networkcontainer,
            'network_view': self.network_view
        }
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) == 0:
                raise InfobloxNotFoundException(
                    "No requested network container found: "
                    + networkcontainer)
            net_ref = r_json[0]['_ref']
            rest_url = self._construct_url(net_ref)
            params = {
                '_function': 'next_available_network',
                'cidr': str(cidr),
                'num': 1
            }
            r = self.s.post(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    if 'code' in r_json and \
                       r_json['code'] == 'Client.Ibap.Data':
                        raise InfobloxNoNetworkAvailableException(
                            r_json['text'])
                    else:
                        raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
            return r_json['networks'][0]
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def update_host_record(self, ref, address, ttl=None):
        """ Implements IBA REST API call to update IBA host record
        :param ref: internal infoblox reference to existing host record
        :param address: new IP for the given 'ref'
        :param ttl: if defined, will override the previous ttl
        """
        if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", address):
            ipv4addr = address
        else:
            raise InfobloxBadInputParameter(
                'Expected IP address format')
        
        rest_url = self._construct_url(ref)
        if ttl is None:
            payload = {
                'ipv4addrs': [{
                    'ipv4addr': ipv4addr
                }]
            }
        else:
            payload = {
                'ipv4addrs': [{
                    'ipv4addr': ipv4addr
                }],
                'use_ttl': True,
                'ttl': ttl
            }
        try:
            r = self.s.put(url=rest_url, data=json.dumps(payload))
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_cname(self, fqdn):
        """ Implements IBA REST API call to retrieve cname record fields
        Returns hash table of fields with field name as a hash key
        :param fqdn: hostname in FQDN
        """
        rest_url = self._construct_url('/record:cname')
        params = {'name': fqdn, 'view': self.dns_view}
        try:
            r = self.s.get(url=rest_url, params=params)
            r_json = r.json()
            if r.status_code != 200:
                if 'text' in r_json:
                    raise InfobloxNotFoundException(r_json['text'])
                else:
                    r.raise_for_status()
            if len(r_json) > 0:
                return r_json[0]
            else:
                raise InfobloxNotFoundException("No hosts found: " + fqdn)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise
