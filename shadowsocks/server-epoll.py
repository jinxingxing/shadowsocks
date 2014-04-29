#coding: utf8

import sys
sys.setrecursionlimit(60)
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
            logging.debug('!!!!!!!!!!! close remote ios %d', 
                self._remote_ios.fileno())
            self._ioloop.remove_handler(self._remote_ios.fileno())
            self._remote_ios._obj.close()

        logging.debug('!!!!!!!!!!! close local ios %d', self._ios.fileno())
        self._ioloop.remove_handler(self._ios.fileno())
        self._ios.close()

    def handle_read(self, fd, events):
        raise NotImplementedError

    def handle_write(self, fd, events):
        raise NotImplementedError

    def handle_error(self, fd, events):
        raise NotImplementedError


class ShadowTunnelHandler(BaseTunnelHandler):
    def __init__(self, *args, **kwargs):
        BaseTunnelHandler.__init__(self, *args, **kwargs)

class ShadowAcceptHandler(ioloop.BaseHandler):
    def __init__(self, _ioloop, srv_socket):
        self._ioloop = _ioloop
        self._srv_socket = srv_socket

    def handle_read(self, fd, events):
        cli_socket, cli_addr = self._srv_socket.accept()
        logging.debug("accept connect[%s] from %s:%s" % (
            cli_socket.fileno(), cli_addr[0], cli_addr[1]))
        cli_socket.setblocking(0)
        ts = TunnelStream(cli_socket)
        handler = LeftTunnelHandler( self._ioloop, ts)
        self._ioloop.add_handler(cli_socket.fileno(), handler, 
            m_read=True, m_write=True) 

def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s # %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    config = parse_options()

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']

    config['method'] = config.get('method', None)
    METHOD = config.get('method')

    config['port_password'] = config.get('port_password', None)
    PORTPASSWORD = config.get('port_password')

    config['timeout'] = config.get('timeout', 600)

    if not KEY and not config_path:
        sys.exit('config not specified, please read https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)

    global G_CONFIG
    G_CONFIG = config

    if PORTPASSWORD:
        if PORT or KEY:
            logging.warn('warning: port_password should not be used with server_port and password. server_port and password will be ignored')
    else:
        PORTPASSWORD = {}
        PORTPASSWORD[str(PORT)] = KEY

    encrypt.init_table(KEY, METHOD)

    io = ioloop.IOLoop()
    import socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind((SERVER, PORT))
    logging.info("listing on %s", str(sock.getsockname()))
    sock.listen(1024)
    io.add_handler(sock.fileno(), ShadowAcceptHandler(io, sock), m_read=True)
    next_tick = time.time() + 10
    count = 0
    while True:
        count += 1
        if time.time() >= next_tick:
            logging.info("loop count %d", count)
            next_tick = time.time() + 10
            pass
        _s = time.time()
        io.wait_events(0.1)
        use_time = time.time() - _s
        if use_time > 0.2:
            logging.error("events process cost time: %f", _e-_s)
        elif use_time < 0.1:
            time.sleep(0.1-use_time)
