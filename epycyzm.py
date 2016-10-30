#!/usr/bin/env python3
'''
Experimental Python CPU (yet) Zcash miner

Inspired by m0mchil's poclbm (thanks!), but heavily rewritten with asyncio.

Miner icon:
http://www.flaticon.com/free-icon/miner_206873

(c) 2016 slush
MIT license
'''

import re
import os
import json
import time
import struct
import asyncio
import binascii
import itertools
import traceback
import threading
import multiprocessing
from hashlib import sha256
from optparse import OptionGroup, OptionParser
from concurrent.futures._base import TimeoutError
from asyncio import coroutine, coroutines, futures

try:
    import PySide
    gui_enabled = True
except ImportError:
    gui_enabled = False

from morpavsolver import Solver
from version import VERSION

class Server(object):
    @classmethod
    def from_url(cls, url):
        # Parses proto://user:password@zec.suprnova.cc:1234#tagname
        s = cls()
        x = re.match(r'^(.*\:\/\/)?((?P<username>.*?)(\:(?P<password>.*?))?\@)?(?P<host>.*?)(\:(?P<port>\d+))?(\#(?P<tag>.*?))?$', url)
        s.username = x.group('username') or ''
        s.password = x.group('password') or ''
        s.host = x.group('host')
        s.port = int(x.group('port') or s.port)
        s.tag = x.group('tag') or s.host # set host if tag not present
        return s

    def __repr__(self):
        return str(self.__dict__)


class ServerSwitcher(object):
    def __init__(self, loop, servers, solvers):
        self.loop = loop
        self.servers = servers
        self.solvers = solvers

    @coroutine
    def run(self):
        for server in itertools.cycle(self.servers):
            try:
                client = StratumClient(self.loop, server, self.solvers)
                yield from client.connect()
            except KeyboardInterrupt:
                print("Closing...")
                self.solvers.stop()
                break
            except:
                traceback.print_exc()

            print("Server connection closed, trying again...")
            yield from asyncio.sleep(5)

class StratumNotifier(object):
    def __init__(self, reader, on_notify):
        self.waiters = {}
        self.on_notify = on_notify
        self.reader = reader
        self.task = None

    def run(self):
        # self.task = asyncio.ensure_future(self.observe())
        self.task = asyncio.async(self.observe())
        return self.task

    @coroutine
    def observe(self):
        try:
            while True:
                data = yield from self.reader.readline()
                if data == b'':
                    raise Exception("Server closed connection.")

                try:
                    msg = json.loads(data.decode())
                except:
                    raise Exception("Recieved corrupted data from server: %s" % data)

                if msg['id'] == None:
                    # It is notification
                    yield from self.on_notify(msg)
                else:
                    # It is response of our call
                    self.waiters[int(msg['id'])].set_result(msg)

        except Exception as e:
            # Do not try to recover from errors, let ServerSwitcher handle this
            traceback.print_exc()
            raise

    @coroutine
    def wait_for(self, msg_id):
        f = asyncio.Future()
        self.waiters[msg_id] = f
        return (yield from asyncio.wait_for(f, 10))

class Job(object):
    @classmethod
    def from_params(cls, params):
        j = cls()
        j.job_id = params[0]
        j.version = binascii.unhexlify(params[1])
        j.prev_hash = binascii.unhexlify(params[2])
        j.merkle_root = binascii.unhexlify(params[3])
        j.reserved = binascii.unhexlify(params[4])
        j.ntime = binascii.unhexlify(params[5])
        j.nbits = binascii.unhexlify(params[6])
        j.clean_job = bool(params[7])

        assert (len(j.version) == 4)
        assert (len(j.prev_hash) == 32)
        assert (len(j.merkle_root) == 32)
        assert (len(j.reserved) == 32)
        assert (len(j.ntime) == 4)
        assert (len(j.nbits) == 4)

        return j

    def set_target(self, target):
        self.target = target

    def build_header(self, nonce):
        assert(len(nonce) == 32)

        header = self.version + self.prev_hash + self.merkle_root + self.reserved + self.ntime + self.nbits + nonce
        assert(len(header) == 140)
        return header

    @classmethod
    def is_valid(cls, header, solution, target):
        assert (len(header) == 140)
        assert (len(solution) == 1344 + 3)

        hash = sha256(sha256(header + solution).digest()).digest()
        print("hash %064x" % int.from_bytes(hash, 'little'))

        return int.from_bytes(hash, 'little') < target

    def __repr__(self):
        return str(self.__dict__)

class CpuSolver(threading.Thread):
    def __init__(self, loop, counter):
        super(CpuSolver, self).__init__()
        self._stop = False
        self.loop = loop
        self.counter = counter

        self.job = None
        self.nonce1 = None
        self.nonce2_int = 0
        self.on_share = None

    def stop(self):
        raise Exception("FIXME")
        self._stop = True

    def set_nonce(self, nonce1):
        self.nonce1 = nonce1

    def new_job(self, job, solver_nonce, on_share):
        self.job = job
        self.solver_nonce = solver_nonce
        self.on_share = on_share

    def increase_nonce(self):
        if self.nonce2_int > 2**62:
            self.nonce2_int = 0

        self.nonce2_int += 1
        return struct.pack('>q', self.nonce2_int)

    def run(self):
        print("Starting CPU solver")
        s = Solver()

        while self.job == None or self.nonce1 == None:
            time.sleep(2)
            print(".", end='', flush=True)

        while not self._stop:
            nonce2 = self.increase_nonce()
            nonce2 = nonce2.rjust(32 - len(self.nonce1) - len(self.solver_nonce), b'\0')

            header = self.job.build_header(self.nonce1 + self.solver_nonce + nonce2)

            sol_cnt = s.find_solutions(header)
            self.counter(sol_cnt) # Increase counter for stats

            for i in range(sol_cnt):
                solution = b'\xfd\x40\x05' + s.get_solution(i)

                if self.job.is_valid(header, solution, self.job.target):
                    print("FOUND VALID SOLUTION!")
                    # asyncio.run_coroutine_threadsafe(self.on_share(self.job, self.solver_nonce + nonce2, solution), self.loop)
                    asyncio.async(self.on_share(self.job, self.solver_nonce + nonce2, solution), loop=self.loop)

class SolverPool(object):
    def __init__(self, loop, gpus=0, cpus=0):
        self.solvers = []
        self.time_start = time.time()
        self.solutions = 0

        for i in range(cpus):
            s = CpuSolver(loop, self.inc_solutions)
            s.start()
            self.solvers.append(s)

    def inc_solutions(self, i):
        self.solutions += i
        print("%.02f H/s" % (self.solutions / (time.time() - self.time_start)))

    def set_nonce(self, nonce1):
        for i, s in enumerate(self.solvers):
            s.set_nonce(nonce1)

    def new_job(self, job, on_share):
        for i, s in enumerate(self.solvers):
            s.new_job(job,
                      # Generate unique nonce1 for each solver
                      struct.pack('>B', i),
                      on_share)

    def stop(self):
        for s in self.solvers:
            s.stop()

# Stratum protocol specification: https://github.com/zcash/zips/pull/78
class StratumClient(object):
    def __init__(self, loop, server, solvers):
        self.loop = loop
        self.server = server
        self.solvers = solvers
        self.msg_id = 0 # counter of stratum messages

        self.writer = None
        self.notifier = None

    @coroutine
    def connect(self):
        print("Connecting to", self.server)
        asyncio.open_connection()
        reader, self.writer = yield from asyncio.open_connection(self.server.host, self.server.port, loop=self.loop)

        # Observe and route incoming message
        self.notifier = StratumNotifier(reader, self.on_notify)
        self.notifier.run()

        yield from self.subscribe()
        yield from self.authorize()

        while True:
            yield from asyncio.sleep(1)

            if self.notifier.task.done():
                # Notifier failed or wanted to stop procesing
                # Let ServerSwitcher catch this and round-robin connection
                raise self.notifier.task.exception() or Exception("StratumNotifier failed, restarting.")

    def new_id(self):
        self.msg_id += 1
        return self.msg_id

    def close(self):
        print('Close the socket')
        self.writer.close()

    @coroutine
    def on_notify(self, msg):
        if msg['method'] == 'mining.notify':
            print("Giving new job to solvers")
            j = Job.from_params(msg['params'])
            j.set_target(self.target)
            self.solvers.new_job(j, self.submit)
            return

        if msg['method'] == 'mining.set_target':
            print("Received set.target")
            self.target = int.from_bytes(binascii.unhexlify(msg['params'][0]), 'big')
            return

        print("Received unknown notification", msg)

    @coroutine
    def authorize(self):
        ret = yield from self.call('mining.authorize', self.server.username, self.server.password)
        if ret['result'] != True:
            raise Exception("Authorization failed: %s" % ret['error'])
        print("Successfully authorized as %s" % self.server.username)

    @coroutine
    def subscribe(self):
        ret = yield from self.call('mining.subscribe', VERSION, None, self.server.host, self.server.port)
        nonce1 = binascii.unhexlify(ret['result'][1])
        print("Successfully subscribed for jobs")
        self.solvers.set_nonce(nonce1)
        return nonce1

    @coroutine
    def submit(self, job, nonce2, solution):
        t = time.time()

        ret = yield from self.call('mining.submit',
                        self.server.username,
                        job.job_id,
                        binascii.hexlify(job.ntime).decode('utf-8'),
                        binascii.hexlify(nonce2).decode('utf-8'),
                        binascii.hexlify(solution).decode('utf-8'))
        if ret['result'] == True:
            print("Share ACCEPTED in %.02fs" % (time.time() - t))
        else:
            print("Share REJECTED in %.02fs" % (time.time() - t))

    @coroutine
    def call(self, method, *params):
        msg_id = self.new_id()
        msg = {"id": msg_id,
               "method": method,
               "params": params}

        data = "%s\n" % json.dumps(msg)
        print('< %s' % data[:200] + (data[200:] and "...\n"), end='')
        self.writer.write(data.encode())

        try:
            #r = asyncio.ensure_future(self.notifier.wait_for(msg_id))
            r = asyncio.async(self.notifier.wait_for(msg_id))
            yield from asyncio.wait([r, self.notifier.task], timeout=30, return_when=asyncio.FIRST_COMPLETED)

            if self.notifier.task.done():
                raise self.notifier.task.exception()

            data = r.result()
            log = '> %s' % data
            print(log[:100] + (log[100:] and '...'))

        except TimeoutError:
            raise Exception("Request to server timed out.")

        return data

def main():
    usage = "usage: %prog [OPTION]... SERVER[#tag]...\n" \
            "SERVER is one or more [stratum+tcp://]user:pass@host:port          (required)\n" \
            "[#tag] is a per SERVER user friendly name displayed in stats (optional)\n" \
            "Example usage: %prog stratum+tcp://slush.miner1:password@zcash.slushpool.com:4444"

    parser = OptionParser(version=VERSION, usage=usage)
    parser.add_option('-g', '--disable-gui', dest='nogui',        action='store_true', help='Disable graphical interface, use console only')
    parser.add_option('-c', '--cpu',         dest='cpu',          default=0,           help='How many CPU solvers to start (-1=disabled, 0=auto)', type='int')
    parser.add_option('-n', '--nice',       dest='nice',          default=0,        help="Niceness of the process (Linux only)", type='int')

    #parser.add_option('--verbose',        dest='verbose',        action='store_true', help='verbose output, suitable for redirection to log file')
    #parser.add_option('-q', '--quiet',    dest='quiet',          action='store_true', help='suppress all output except hash rate display')
    #parser.add_option('--proxy',          dest='proxy',          default='',          help='specify as [[socks4|socks5|http://]user:pass@]host:port (default proto is socks5)')
    #parser.add_option('--no-ocl',         dest='no_ocl',         action='store_true', help="don't use OpenCL")
    #parser.add_option('-d', '--device',   dest='device',         default=[],          help='comma separated device IDs, by default will use all (for OpenCL - only GPU devices)')

    #group = OptionGroup(parser, "Miner Options")
    #group.add_option('-r', '--rate',          dest='rate',       default=1,       help='hash rate display interval in seconds, default=1 (60 with --verbose)', type='float')
    #group.add_option('-e', '--estimate',      dest='estimate',   default=900,     help='estimated rate time window in seconds, default 900 (15 minutes)', type='int')
    #group.add_option('-t', '--tolerance',     dest='tolerance',  default=2,       help='use fallback pool only after N consecutive connection errors, default 2', type='int')
    #group.add_option('-b', '--failback',      dest='failback',   default=60,      help='attempt to fail back to the primary pool after N seconds, default 60', type='int')
    #group.add_option('--cutoff-temp',         dest='cutoff_temp',default=[],      help='AMD GPUs only. For GPUs requires github.com/mjmvisser/adl3. Comma separated temperatures at which to skip kernel execution, in C, default=95')
    #group.add_option('--cutoff-interval',     dest='cutoff_interval',default=[],  help='how long to not execute calculations if CUTOFF_TEMP is reached, in seconds, default=0.01')
    #group.add_option('--no-server-failbacks', dest='nsf',        action='store_true', help='disable using failback hosts provided by server')
    #parser.add_option_group(group)

    #group = OptionGroup(parser,
    #    "OpenCL Options",
    #    "Every option except 'platform' and 'vectors' can be specified as a comma separated list. "
    #    "If there aren't enough entries specified, the last available is used. "
    #    "Use --vv to specify per-device vectors usage."
    #)
    #group.add_option('-p', '--platform', dest='platform',   default=-1,          help='use platform by id', type='int')
    #group.add_option('-w', '--worksize', dest='worksize',   default=[],          help='work group size, default is maximum returned by OpenCL')
    #group.add_option('-f', '--frames',   dest='frames',     default=[],          help='will try to bring single kernel execution to 1/frames seconds, default=30, increase this for less desktop lag')
    #group.add_option('-s', '--sleep',    dest='frameSleep', default=[],          help='sleep per frame in seconds, default 0')
    #group.add_option('--vv',             dest='vectors',    default=[],          help='use vectors, default false')
    #group.add_option('-v', '--vectors',  dest='old_vectors',action='store_true', help='use vectors')
    #parser.add_option_group(group)
    #options.rate = max(options.rate, 60) if options.verbose else max(options.rate, 0.1)
    #options.max_update_time = 60
    #options.device = tokenize(options.device, 'device', [])
    #options.cutoff_temp = tokenize(options.cutoff_temp, 'cutoff_temp', [95], float)
    #options.cutoff_interval = tokenize(options.cutoff_interval, 'cutoff_interval', [0.01], float)

    (options, options.servers) = parser.parse_args()
    options.version = VERSION

    servers = [ Server.from_url(s) for s in options.servers]
    if len(servers) == 0:
        parser.print_usage()
        return

    if options.nice is not 0:
        print("Setting proces niceness to %d" % os.nice(options.nice))

    if options.cpu == -1:
        cpus = 0
    elif options.cpu == 0:
        cpus = multiprocessing.cpu_count()
    else:
        cpus = options.cpu

    global gui_enabled
    if options.nogui:
        gui_enabled = False
    elif not gui_enabled:
        print("GUI disabled, please install PySide/Qt first.")

    print("Using %d CPU solver instances" % cpus)
    print(servers)

    loop = asyncio.get_event_loop()

    solvers = SolverPool(loop, gpus=0, cpus=cpus)
    switcher = ServerSwitcher(loop, servers, solvers)
    loop.run_until_complete(switcher.run())

    loop.close()

if __name__ == '__main__':
    main()
