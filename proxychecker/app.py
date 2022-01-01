#    DATE: 9 Dec 2021 - Today
#  AUTHOR: Roman Bergman <roman.bergman@protonmail.com>
# LICENSE: AGPL3.0
# VERSION: 0.3.10


import os
import re
import sys
import glob
import time
import logging
import argparse
import requests
import threading
import urllib.parse
import concurrent.futures


class ProxyChecker():
    def __init__(self):
        self.args = self.get_argv()
        logging.basicConfig(format=' ' * 100 + '\r%(asctime)s.%(msecs)03d: %(levelname)s: %(message)s',
                            level=getattr(logging, self.args.log.upper(), None), datefmt="%H:%M:%S")
        self.config = {'proxy_judge': 'http://azenv.net/'}
        self.counters = {'proxy_total': 0,
                         'proxy_check': 0}
        self.proxy = {'http':    [],
                      'https':   [],
                      'socks4':  [],
                      'socks4a': [],
                      'socks5':  [],
                      'socks5h': []}

    def get_argv(self):
        """
        TODO: NEED REFACTORING AND RENAME FUNC
        """
        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)
        parser.add_argument('-h', '--help', action='help', help='\tShow this help message and exit')
        parser.add_argument('--log', default='info', help='\tLevel logging: WARNING, ERROR, INFO, DEBUG. Default: INFO.')

        pg_check = parser.add_argument_group(title='CHECK PARAMS')
        pg_check.add_argument('--check', action='store', type=str, help='\tSite for proxy check.')
        pg_check.add_argument('--timeout', action='store', type=int, default=10, help='\tTime out for request in seconds. Default: 10 sec.')
        pg_check.add_argument('-t', '--threads', action='store', type=int, default=32, help='\tThe number of simultaneous threads for checking proxy.')


        pg_in = parser.add_argument_group(title='INPUT PROXY')
        pg_in.add_argument('-i', '--proxyPath', action='store', type=str, required=True, help='\tPath for proxy file or directory.')
        pg_in.add_argument('--prefix', action='store', type=str, default='txt', help='\tFile prefix, use with directory search proxy file.')

        pg_out = parser.add_argument_group(title='OUTPUT PROXY')
        pg_out.add_argument('-o', '--out', action='store', type=str, default='proxy', help='\tOutput file name.')
        pg_out.add_argument('--single', action='store_true', default=False, help='\tSave proxy to single file.')

        if len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(1)
        else:
            return parser.parse_args()

    def get_proxy(self, path, prefix):
        def _read_proxy_file(path_list):
            _proxy_list = []
            proxy_pattern_search = re.compile(r'''[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\:[0-9]+\s''')
            for item_file_path in path_list:
                with open(item_file_path, 'r') as fr:
                    for item_proxy in proxy_pattern_search.findall(fr.read()):
                        ip, port = item_proxy.rstrip().split(':')
                        if not [ip, port] in _proxy_list:
                            _proxy_list.append([ip, port])
            self.counters['proxy_total'] = len(_proxy_list)
            logging.debug('GET proxy count: {}'.format(self.counters['proxy_total']))
            return _proxy_list

        if os.path.isfile(path):
            return _read_proxy_file([path])
        elif os.path.isdir(path):
            path_list = glob.glob('{}/*.{}'.format(path.rstrip('/'), prefix))
            if path_list:
                return _read_proxy_file(path_list)
            else:
                logging.error('Input proxy files NOT FOUND.')
                sys.exit(0)
        else:
            logging.error('Proxy file or path not found.')
            sys.exit(0)

    def save_proxy(self, proxy_dict):
        """
        TODO: NEED REFACTORING AND RENAME FUNC
        """
        if self.args.single:
            with open('{}_ALL.txt'.format(self.args.out), 'w') as fw:
                for item_schema in ['http', 'https', 'socks4', 'socks5', 'socks5h']:
                    if len(proxy_dict[item_schema]):
                        for item_proxy in proxy_dict[item_schema]:
                            if item_schema == 'socks5h':
                                schema = 'socks5'
                            else:
                                schema = item_schema
                            fw.write('{}:{}:{}\n'.format(schema, item_proxy[0], item_proxy[1]))
            logging.info('Proxy saved to: {}_ALL.txt'.format(self.args.out))
        else:
            for item_schema in ['http', 'https', 'socks4', 'socks5h']:
                if len(proxy_dict[item_schema]):
                    with open('{}_{}.txt'.format(self.args.out, item_schema.upper()), 'w') as fw:
                        for item_proxy in proxy_dict[item_schema]:
                            if item_schema == 'socks5h':
                                schema = 'socks5'
                            else:
                                schema = item_schema
                            fw.write('{}:{}:{}\n'.format(schema, item_proxy[0], item_proxy[1]))
                    logging.info('Proxy saved to: {}_{}.txt'.format(self.args.out, item_schema.upper()))

    def check_proxy(self, proxy_item):
        for item_schema in ['socks5h', 'socks4', 'https', 'http']:
            if self.args.check:
                check_ip_site = self.args.check
            else:
                check_ip_site = self.config['check_ip_sites']
            headers = {'Host': urllib.parse.urlparse(check_ip_site).netloc,
                       'Connection': 'keep-alive',
                       'X-Requested-With': 'XMLHttpRequest',
                       'User-Agent': 'Mozilla/6.0 (Windows NT 10.0; Win64; x64) AppleWebKit/567.36 (KHTML, like Gecko) Chrome/78.0.3201.169 Safari/567.36'}
            try:
                req = requests.get(check_ip_site, headers=headers,
                                   proxies={urllib.parse.urlparse(check_ip_site).scheme: '{}://{}:{}'.format(item_schema, proxy_item[0], proxy_item[1])},
                                   timeout=self.args.timeout)
                if req.status_code == 200:
                    self.proxy[item_schema].append(proxy_item)
                    break
            except Exception as err:
                logging.debug(err)
        self.counters['proxy_check'] += 1

    def progressbar(self):
        """
        TODO: NEED REFACTORING AND RENAME FUNC
        """
        def _bar_thread():
            while True:
                sys.stdout.write(str('\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\r'))
                sys.stdout.write('Proxy total: {};    Proxy check: {};   Proxy valid: {};'.format(
                                    self.counters['proxy_total'],
                                    self.counters['proxy_check'],
                                    len(self.proxy['http'])
                                        + len(self.proxy['https'])
                                        + len(self.proxy['socks4'])
                                        + len(self.proxy['socks5'])))
                time.sleep(0.1)
        progress = threading.Thread(target=_bar_thread)
        progress.daemon = True
        progress.start()

    def proxy_handler(self):
        """
        TODO: NEED REFACTORING AND RENAME FUNC
        """
        try:
            _proxy_list = self.get_proxy(self.args.proxyPath, self.args.prefix)
            self.progressbar()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                executor.map(self.check_proxy, _proxy_list)
            self.save_proxy(self.proxy)
            sys.stdout.write('\n')
        except KeyboardInterrupt:
            self.save_proxy(self.proxy)


def main():
    ProxyChecker().proxy_handler()
