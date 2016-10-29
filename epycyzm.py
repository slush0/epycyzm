#!/usr/bin/env python3
'''
Experimental Python CPU (yet) Zcash miner

Inspired by m0mchil's poclbm (thanks!), but heavily rewritten with asyncio.

(c) 2016 slush
MIT license
'''

import re
import asyncio
import json
import struct
import time
import itertools
import traceback
import binascii
import threading
import multiprocessing
from hashlib import sha256
from optparse import OptionGroup, OptionParser

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

    async def run(self):
        for server in itertools.cycle(self.servers):
            client = StratumClient(self.loop, server, self.solvers)

            try:
                await client.connect()
            except KeyboardInterrupt:
                print("Closing...")
                self.solvers.stop()
                break
            except Exception as e:
                traceback.print_exc()

            print("Server connection closed, trying again...")
            time.sleep(2)

class StratumNotifier(object):
    def __init__(self, reader, on_stop, on_notify):
        self.waiters = {}
        self.on_stop = on_stop
        self.on_notify = on_notify

        asyncio.ensure_future(self.observe(reader))

    async def observe(self, reader):
        try:
            while True:
                data = await reader.readline()
                msg = json.loads(data.decode())

                if msg['id'] == None:
                    # It is notification
                    await self.on_notify(msg)
                else:
                    # It is response of our call
                    self.waiters[int(msg['id'])].set_result(msg)

        except Exception as e:
            # Do not try to recover from errors, let ServerSwitcher handle this
            traceback.print_exc()
            self.on_stop.set_exception(e)

    async def wait_for(self, msg_id):
        f = asyncio.Future()
        self.waiters[msg_id] = f
        return await f

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

        hash = sha256(sha256(header + solution).digest()).digest()[::-1]

        print("hash", int.from_bytes(hash, 'big'))

        if int.from_bytes(hash, 'big') < int.from_bytes(target, 'big'):
            print(binascii.hexlify(hash).ljust(64, b'0'))
            return True
        return False

    def __repr__(self):
        return str(self.__dict__)

class CpuSolver(threading.Thread):
    def __init__(self, loop, counter):
        super(CpuSolver, self).__init__()
        self._stop = False
        self.loop = loop
        self.counter = counter

        self.job = None
        self.nonce1 = b''
        self.nonce2_int = 0
        self.on_share = None

    def stop(self):
        raise Exception("FIXME")
        self._stop = True

    def new_job(self, job, nonce1, solver_nonce, on_share):
        self.job = job
        self.nonce1 = nonce1
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

        while self.job == None:
            time.sleep(0.1)
            print("Waiting for jobs")

        while not self._stop:
            nonce2 = self.increase_nonce()
            nonce2 = nonce2.rjust(32 - len(self.nonce1) - len(self.solver_nonce), b'\0')

            header = self.job.build_header(self.nonce1 + self.solver_nonce + nonce2)

            sol_cnt = s.find_solutions(header)
            self.counter(sol_cnt) # Increase counter for stats

            for i in range(sol_cnt):
                solution = binascii.unhexlify('fd4005') + s.get_solution(i)

                if self.job.is_valid(header, solution, self.job.target):
                    print("FOUND VALID SOLUTION!")
                    asyncio.run_coroutine_threadsafe(self.on_share(self.job, self.solver_nonce + nonce2, solution), self.loop)

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

    def new_job(self, job, nonce1, on_share):
        print("Giving new job to solvers")
        for i, s in enumerate(self.solvers):
            s.new_job(job, nonce1,
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
        self.on_stop = asyncio.Future()

        self.writer = None
        self.notifier = None
        self.nonce1 = None

    async def connect(self):
        print("Connecting to", self.server)
        asyncio.open_connection()
        reader, self.writer = await asyncio.open_connection(self.server.host, self.server.port, loop=self.loop)

        # Observe and route incoming message
        self.notifier = StratumNotifier(reader, self.on_stop, self.on_notify)

        self.nonce1 = await self.subscribe()
        await self.authorize()


        while True:

            await asyncio.sleep(10)

            if self.on_stop.done():
                # Some component failed or wanted to stop procesing
                # Let ServerSwitcher catch this and round-robin connection
                raise self.on_stop.exception()

    def new_id(self):
        self.msg_id += 1
        return self.msg_id

    def close(self):
        print('Close the socket')
        self.writer.close()

    async def on_notify(self, msg):
        print("Received notification", msg)
        if msg['method'] == 'mining.notify':
            print("Received mining.notify")
            j = Job.from_params(msg['params'])
            j.set_target(self.target)
            self.solvers.new_job(j, self.nonce1, self.submit)
            return

        if msg['method'] == 'mining.set_target':
            print("Received set.target")
            self.target = binascii.unhexlify(msg['params'][0])
            return

    async def authorize(self):
        ret = await self.call('mining.authorize', self.server.username, self.server.password)
        if ret['result'] != True:
            raise Exception("Authorization failed: %s" % ret['error'])
        print("Successfully authorized as %s" % self.server.username)

    async def subscribe(self):
        ret = await self.call('mining.subscribe', VERSION, None, self.server.host, self.server.port)
        nonce1 = binascii.unhexlify(ret['result'][1])
        print("Successfully subscribed for jobs")
        return nonce1

    async def submit(self, job, nonce2, solution):
        ret = await self.call('mining.submit',
                        self.server.username,
                        job.job_id,
                        binascii.hexlify(job.ntime).decode('utf-8'),
                        binascii.hexlify(nonce2).decode('utf-8'),
                        binascii.hexlify(solution).decode('utf-8'))

    async def call(self, method, *params):
        msg_id = self.new_id()
        msg = {"id": msg_id,
               "method": method,
               "params": params}

        data = "%s\n" % json.dumps(msg)
        print('< %s' % data, end='')
        self.writer.write(data.encode())

        data = await self.notifier.wait_for(msg_id)
        print('> %s' % data)
        return data

def main():
    usage = "usage: %prog [OPTION]... SERVER[#tag]...\n" \
            "SERVER is one or more [stratum+tcp://]user:pass@host:port          (required)\n" \
            "[#tag] is a per SERVER user friendly name displayed in stats (optional)\n" \
            "Example usage: %prog stratum+tcp://slush.miner1:password@zcash.slushpool.com:4444"

    parser = OptionParser(version=VERSION, usage=usage)
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

    print(servers)

    loop = asyncio.get_event_loop()

    solvers = SolverPool(loop, gpus=0, cpus=multiprocessing.cpu_count())
    switcher = ServerSwitcher(loop, servers, solvers)
    loop.run_until_complete(switcher.run())

    loop.close()

if __name__ == '__main__':
    main()
