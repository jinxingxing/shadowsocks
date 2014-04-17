#coding: utf8

import sys
sys.setrecursionlimit(30)
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

import socket
import struct
import os
import time
import errno
import logging
import getopt
import encrypt
import utils
import ioloop

def parse_options():
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except:
        pass
    print 'shadowsocks %s' % version

    KEY = None
    METHOD = None
    IPv6 = False

    config_path = utils.find_config()
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:m:c:6')
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            try:
                f = open(config_path, 'rb')
                config = json.load(f)
            except ValueError as e:
                logging.error('found an error in config.json: %s', e.message)
                sys.exit(1)
        else:
            config = {}

        optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:m:c:6')
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = value
            elif key == '-s':
                config['server'] = value
            elif key == '-m':
                config['method'] = value
            elif key == '-6':
                IPv6 = True
    except getopt.GetoptError:
        utils.print_server_help()
        sys.exit(2)

    return config

class TunnelStream(ioloop.SocketStream): 
    def read(self, *args, **kwargs):
        s = ioloop.SocketStream.read(self, *args, **kwargs)
        return s
    def real_write(self, *args, **kwargs):
        ioloop.SocketStream.real_write(self, *args, **kwargs)

class BaseTunnelHandler(ioloop.BaseHandler):
    def __init__(self, *args, **kwargs):
        ioloop.BaseHandler.__init__(self, *args, **kwargs)
        self.encryptor = encrypt.Encryptor(G_CONFIG["password"], G_CONFIG["method"])
        self._ios = None
        self._remote_ios = None
        self._connecting = False
        self._closing = False

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def close_tunnel(self):
        self._closing =  True
        if self._remote_ios:
            logging.debug('!!!!!!!!!!! close remote ios %d', self._remote_ios.fileno())
            self._ioloop.remove_handler(self._remote_ios.fileno())
            self._remote_ios._obj.close()

        logging.debug('!!!!!!!!!!! close local ios %d', self._ios.fileno())
        self._ioloop.remove_handler(self._ios.fileno())
        self._ios.close()

    def handle_read(self, fd, events):
        

    def handle_write(self, fd, events):
        raise

    def handle_error(self, fd, events):
        raise


class ShadowTunnelHandler(BaseTunnelHandler):
    def __init__(self, *args, **kwargs):
        BaseTunnelHandler.__init__(self, *args, **kwargs)

