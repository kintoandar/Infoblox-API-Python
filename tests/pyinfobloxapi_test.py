#!/usr/bin/env python
import pyinfobloxapi
import unittest 
from mock import Mock


class Test(unittest.TestCase):
    def setUp(self):
        self.ip = "127.0.0.1"
        self.user = "admin"
        self.password = "password"
        self.api = "1.6"
        self.dns_view = "default"
        self.net_view = "default"
        self.iba = pyinfobloxapi.Infoblox(self.ip,
                                          self.user,
                                          self.password,
                                          self.api,
                                          self.dns_view,
                                          self.net_view)
        self.s = Mock()
 
    def test__construct_url(self):
        endpoint = "/range"
        url = "https://127.0.0.1/wapi/v1.6"
        self.assertEqual(url + endpoint,
                         self.iba._construct_url(endpoint))
        endpoint = "range"
        self.assertEqual(url + "/" + endpoint,
                         self.iba._construct_url(endpoint))

    def test__setup_session(self):
        self.assertEqual(self.iba.s.auth, (self.user, self.password))        

    def test__extract_record(self):
        re1 = "record:host/ZG5zLmhvc3QkLl9kZWZhdWx0LmJldGZhaXIuZGV2Lm54dHpvby" \
              "1iNzFiM2Y:nxtzoo-b71b3f.dev.betfair/default"
        re2 = "cenas"
        self.assertEqual(self.iba._extract_record(re1), 
                         'nxtzoo-b71b3f.dev.betfair')        
        self.assertEqual(self.iba._extract_record(re2), '')        

    def test_create_host_record(self):
        pass


if __name__ == '__main__':
    unittest.main() 
