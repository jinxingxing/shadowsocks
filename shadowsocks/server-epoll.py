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
import traceback

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
    def __init__(self, obj, _ioloop):
        self._ioloop = _ioloop
        self._fd = obj.fileno()
        self._obj = obj 
        self._lbuf = []

    def read(self, *args, **kwargs):
        s = ioloop.SocketStream.read(self, *args, **kwargs)
        return s

    def write(self, data, *args, **kwargs):
        # logging.debug('TunnelStream.write()')
        # ioloop.SocketStream.write(self, data, *args, **kwargs)
        if len(data) == 0:
            return
        self._lbuf.append(data)
        # logging.debug('TunnelStream[%d].write() buf len %d', self._fd, len(self._lbuf))
        # self.real_write()
        self._ioloop.modify_events(self._fd, True, True)

    def real_write(self, *args, **kwargs):
        # ioloop.SocketStream.real_write(self, *args, **kwargs)
        # logging.debug('TunnelStream[%d].real_write() buf len %d', self._fd, len(self._lbuf))
        while self._lbuf:
            data = self._lbuf[0]
            try:
                # self._obj.setblocking(1)
                sl = self._obj.send(data)
                # logging.debug("fd %d, send %d bytes, real send %d", self._obj.fileno(), len(data), sl)
                if sl != len(data):
                    self._lbuf[0] = data[sl:]
                else:
                    del self._lbuf[0]
            except socket.error, _e:
                if _e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    logging.debug('real_write(), socket.error %s', errno.errorcode.get(_e.errno, None))
                    return 
            finally:
                # self._obj.setblocking(0)
                pass

        self._ioloop.modify_events(self._fd, True, False)

    def __len__(self):
       return len(self._lbuf)

class BaseTunnelHandler(ioloop.IOHandler):
    def __init__(self, _ioloop, _ios, *args, **kwargs):
        ioloop.IOHandler.__init__(self, _ioloop, _ios)
        self.encryptor = encrypt.Encryptor(G_CONFIG["password"], G_CONFIG["method"])
        self._ioloop = _ioloop
        self._ios = _ios
        self._remote_ios = None
        self._closing = False

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

class ShadowClientConnHandler(BaseTunnelHandler):
    def __init__(self, _ioloop, _ios, *args, **kwargs):
        BaseTunnelHandler.__init__(self, _ioloop, _ios, *args, **kwargs)
        self._connecting = False

    def handle_read(self, fd, events):
        self.connect_to_remote()

    def connect_to_remote(self):
        if self._connecting:
            return

        self._connecting = True
        rfile = self._ios
        iv_len = self.encryptor.iv_len()
        if iv_len:
            self.decrypt(rfile.read(iv_len))
        addrtype = ord(self.decrypt(rfile.read(1)))
        if addrtype == 1:
            addr = socket.inet_ntoa(self.decrypt(rfile.read(4)))
        elif addrtype == 3:
            addr = self.decrypt(rfile.read(ord(self.decrypt(rfile.read(1)))))
        elif addrtype == 4:
            addr = socket.inet_ntop(socket.AF_INET6, self.decrypt(rfile.read(16)))
        else:
            # not supported
            logging.warn('addr_type(%r) not supported, maybe wrong password', addrtype)
            return
        port = struct.unpack('>H', self.decrypt(rfile.read(2)))[0]
        try:
            logging.info('connecting to remote %s:%d', addr, port)
            _start_time = time.time()
            remote_socket = socket.socket()
            remote_socket.setblocking(0)

            try:
                # ret = remote_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                # logging.info("ret: %r", ret)
                remote_socket.connect((addr, port))
            except socket.error, _e:
                if _e.errno != errno.EINPROGRESS:
                    raise _e

            # logging.info('socket.connect() cost time: %f', time.time()-_start_time)
        except socket.error, e:
            # Connection refused
            logging.warn(e)
            return

        remote_ts = TunnelStream(remote_socket, self._ioloop)
        handler = ShadowRemoteConnHandler(self._ioloop, self._ios, remote_ts)
        self._ioloop.add_handler(remote_ts.fileno(), handler, m_read=True, m_write=True) 
        return

class ShadowRemoteConnHandler(BaseTunnelHandler):
    def __init__(self, _ioloop, _ios, _remote_ios, *args, **kwargs):
        BaseTunnelHandler.__init__(self, _ioloop, _ios, *args, **kwargs)
        self._client_ios = _ios
        self._remote_ios = _remote_ios

    def handle_write(self, fd, events):
        self.handle_connect_result(fd, events)

    def handle_read(self, fd, events):
        self.handle_connect_result(fd, events)

    def handle_error(self, fd, events):
        self.handle_connect_result(fd, events)

    def handle_connect_result(self, fd, events):
        import errno
        ret = self._remote_ios._obj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if ret != 0:
            logging.info("!!!!!!!!!!!! none-block connect, error_no: %d(%s)", ret, errno.errorcode.get(ret, None))
            self._ios.close()
            return

        self._ioloop.remove_handler(self._client_ios.fileno())
        self._ioloop.remove_handler(self._remote_ios.fileno())

        handler = ShadowTunnelHandler(self._ioloop, self._client_ios, self._remote_ios)
        self._ioloop.add_handler(self._client_ios.fileno(), handler, m_read=True, m_write=False)
        self._ioloop.add_handler(self._remote_ios.fileno(), handler, m_read=True, m_write=False)

        logging.info('New tunnel %d <=> %d' % ( self._client_ios.fileno(), self._remote_ios.fileno()))

class ShadowTunnelHandler(BaseTunnelHandler):
    def __init__(self, _ioloop, _ios, _remote_ios, *args, **kwargs):
        BaseTunnelHandler.__init__(self, _ioloop, _ios, *args, **kwargs)
        self._remote_ios = _remote_ios
        self._client_ios = _ios
        self._fd_tuple = (self._ios.fileno(), self._remote_ios.fileno())
        self._fd_ios_map = {
            self._ios.fileno():self._ios,
            self._remote_ios.fileno():self._remote_ios
        }

    def close_fd(self, fd):
        this_ios = self._fd_ios_map[fd]
        del self._fd_ios_map[fd]

        self._closing = True
        logging.debug('!!!!!!!!!!! close fd %d', this_ios.fileno())
        self._ioloop.remove_handler(this_ios.fileno())
        this_ios.safe_close()

        if not self._fd_ios_map:
            logging.info('closed tunnel %d <=> %d', self._fd_tuple[0], self._fd_tuple[1])

    def handle_write(self, fd, events):
        """fd 可写事件出现"""
        if fd not in self._fd_ios_map:
            return 

        write_ios = self._fd_ios_map[fd]
        write_ios.real_write()

        if self._closing:
            self.close_fd(fd)

    def handle_error(self, fd, events):
        self.close_fd(fd)

    def handle_read(self, fd, events):
        try:
            _s = time.time()
            assert fd in self._fd_ios_map
            if  fd == self._fd_tuple[1]:
                write_ios = self._client_ios
            else:
                write_ios = self._remote_ios

            if len(write_ios) >= 256: # 256*4096 = 1M
                # self.handle_write(write_ios.fileno(), 0)
                return 
                # logging.warn("fd %d, buf len %d, close it", write_ios.fileno(), len(write_ios))
                # for t_fd in self._fd_ios_map.keys():
                #    self.close_fd(t_fd)

            if  fd == self._fd_tuple[1]:
                s = self._remote_ios.read(4096)
                s = self.encrypt(s)
            else:
                s = self._client_ios.read(4096)
                s = self.decrypt(s)

            if len(s) == 0:
                logging.debug('iostream[%s].read() return len(s) == 0, close it', self._fd)
                self.close_fd(fd)
                return
            logging.debug("read %d bytes from fd:%d, tunnel: %d <=> %d, Handler: %r", 
                        len(s), fd, self._fd_tuple[0], self._fd_tuple[1], self)

            write_ios.write(s)
                
            # TODO: 写入数据后才监听可写事件
            # self._ioloop._wait_w_fd_set.add(write_ios.fileno())
            return

        except socket.error, _e:
            if _e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                logging.debug('socket error, %s', _e)
                return
            else:
                traceback.print_exc()
                raise _e

class ShadowAcceptHandler(ioloop.BaseHandler):
    def __init__(self, _ioloop, srv_socket):
        self._ioloop = _ioloop
        self._srv_socket = srv_socket

    def handle_read(self, fd, events):
        cli_socket, cli_addr = self._srv_socket.accept()
        logging.debug("accept connect[%s] from %s:%s" % (
            cli_socket.fileno(), cli_addr[0], cli_addr[1]))

        cli_socket.setblocking(0)
        ts = TunnelStream(cli_socket, self._ioloop)
        handler = ShadowClientConnHandler( self._ioloop, ts)
        self._ioloop.add_handler(cli_socket.fileno(), handler, m_read=True) 

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

    config['timeout'] = config.get('timeout', 60)
    socket.setdefaulttimeout(config['timeout'])

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

    logging.info("init table")
    encrypt.init_table(KEY, METHOD)
    logging.info("init table done")

    io = ioloop.IOLoop()
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind((SERVER, PORT))
    logging.info("listing on %s", str(sock.getsockname()))
    sock.listen(1024)
    io.add_handler(sock.fileno(), ShadowAcceptHandler(io, sock), m_read=True)
    try:
        while 1:
            _s = time.time()
            io.wait_events(0.1)
            use_time = time.time() - _s
            if use_time > 0.2:
                logging.error("events process cost time: %f", use_time)
            elif use_time < 0.01:
                time.sleep(0.01-use_time)
    except KeyboardInterrupt, e:
        for fd in io._fd_map:
            logging.debug("os.close(%d)", fd)
            os.close(fd)
        print ""

if __name__ == '__main__':
        main()
