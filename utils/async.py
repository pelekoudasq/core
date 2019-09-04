import os
import importlib
from multiprocessing import Semaphore, Queue as mpQueue
from queue import Empty, Full
from select import select
from os import (fork, kill, getpid, waitpid, ftruncate, lseek, fstat,
                read, write, unlink, open as os_open, close,
                O_CREAT, O_RDWR, O_APPEND, SEEK_CUR, SEEK_SET)
from time import sleep
from hashlib import sha256
from fcntl import flock, LOCK_EX, LOCK_UN
from marshal import loads as marshal_loads, dumps as marshal_dumps
import inspect
from collections import deque
from signal import SIGKILL
from errno import ESRCH
from Crypto import Random


class EOF(Exception):
    pass


MV_ASYNCARGS = '=ASYNCARGS='
MV_EXCEPTION = '=EXCEPTION='


def wait_read(fd, block=True, timeout=0):
    if block:
        timeout = None
    while 1:
        r, w, x = select([fd], [], [], timeout)
        if not r:
            if not block:
                raise Empty()
            else:
                raise EOF("Select Error")
        if block:
            st = fstat(fd)
            if not st.st_size:
                sleep(0.01)
                continue


def read_all(fd, size):
    got = 0
    s = ''
    while got < size:
        r = read(fd, size-got)
        if not r:
            break
        got += len(r)
        s += r
    return s


def wait_write(fd, block=True, timeout=0):
    if block:
        timeout = None
    r, w, x = select([], [fd], [], timeout)
    if not w:
        if not block:
            raise Full()
        else:
            raise EOF("Write Error")


def write_all(fd, data):
    size = len(data)
    written = 0
    while written < size:
        w = write(fd, buffer(data, written, size-written))
        # w = write(fd, memoryview(bytes(data[written: size], 'utf-8')))
        if not w:
            m = "Write EOF"
            raise EOF(m)
        written += w
    return written


class CheapQueue(object):
    _initpid = None
    _pid = _initpid
    _serial = 0

    @classmethod
    def atfork(cls):
        cls._pid = getpid()

    def __init__(self):
        pid = getpid()
        self._initpid = pid
        self._pid = None
        serial = CheapQueue._serial + 1
        CheapQueue._serial = serial
        self.serial = serial
        self.frontfile = '/dev/shm/cheapQ.%s.%s.front' % (pid, serial)
        self.backfile = '/dev/shm/cheapQ.%s.%s.back' % (pid, serial)
        self.front_fd = None
        self.back_fd = None
        self.front_sem = Semaphore(0)
        self.back_sem = Semaphore(0)
        self.getcount = 0
        self.putcount = 0
        self.get_input = self.init_input
        self.get_output = self.init_output

    def init(self):
        frontfile = self.frontfile
        self.front_fd = os_open(frontfile, O_RDWR|O_CREAT|O_APPEND, 0o600)
        backfile = self.backfile
        self.back_fd = os_open(backfile, O_RDWR|O_CREAT|O_APPEND, 0o600)
        self._pid = getpid()
        del self.get_output
        del self.get_input

    def __del__(self):
        try:
            close(self.front_fd)
            close(self.back_fd)
            unlink(self.frontfile)
            unlink(self.backfile)
        except:
            pass

    def init_input(self):
        self.init()
        return self.get_input()

    def init_output(self):
        self.init()
        return self.get_output()

    def get_input(self):
        if self._pid == self._initpid:
            return self.front_sem, self.front_fd
        else:
            return self.back_sem, self.back_fd

    def get_output(self):
        if self._pid == self._initpid:
            return self.back_sem, self.back_fd
        else:
            return self.front_sem, self.front_fd

    def down(self, sema, timeout=None):
        #if timeout is None:
        #    print ("REQ DOWN %d %d %d [%d %d]"
        #            % (self.serial, getpid(), sema._semlock.handle,
        #               self.front_sem._semlock.handle,
        #               self.back_sem._semlock.handle))
        ret = sema.acquire(True, timeout=timeout)
        #if ret:
        #    print "DOWN %d %d" % (self.serial, getpid())
        return ret

    def up(self, sema, timeout=None):
        sema.release()
        #print ("UP %d %d %d [%d %d]"
        #        % (self.serial, getpid(), sema._semlock.handle,
        #           self.front_sem._semlock.handle,
        #           self.back_sem._semlock.handle))

    def put(self, obj, block=True, timeout=0):
        data = marshal_dumps(obj)
        sema, fd = self.get_output()
        #if self._pid == self._initpid:
        #    print "> PUT  ", getpid(), self.serial, self.putcount, '-'
        #else:
        #    print "  PUT <", getpid(), self.serial, self.putcount, '-'
        chk = sha256(data).digest()
        flock(fd, LOCK_EX)
        try:
            write_all(fd, "%016x%s" % (len(data), chk))
            write_all(fd, data)
        finally:
            flock(fd, LOCK_UN)
            self.up(sema)
        self.putcount += 1

    def get(self, block=True, timeout=0):
        if block:
            timeout=None
        sema, fd = self.get_input()
        #if self._pid == self._initpid:
        #    print "< GET  ", getpid(), self.serial, self.getcount, '-'
        #else:
        #    print "  GET >", getpid(), self.serial, self.getcount, '-'
        if not self.down(sema, timeout=timeout):
            raise Empty()
        flock(fd, LOCK_EX)
        try:
            header = read_all(fd, 48)
            chk = header[16:]
            header = header[:16]
            size = int(header, 16)
            data = read_all(fd, size)
            pos = lseek(fd, 0, SEEK_CUR)
            if pos > 1048576:
                st = fstat(fd)
                if pos >= st.st_size:
                    ftruncate(fd, 0)
                    lseek(fd, 0, SEEK_SET)
        finally:
            flock(fd, LOCK_UN)
        _chk = sha256(data).digest()
        if chk != _chk:
            raise AssertionError("Corrupt Data!")
        obj = marshal_loads(data)
        self.getcount += 1
        return obj


Queue = mpQueue
if os.path.exists("/dev/shm"):
    Queue = CheapQueue


def async_call(func, args, kw, channel):
    argspec = inspect.getargspec(func)
    if argspec.keywords or 'async_channel' in argspec.args:
        kw['async_channel'] = channel
    return func(*args, **kw)


def async_worker(link):
    while 1:
        inp = link.receive()
        if inp is None:
            break
        try:
            if not isinstance(inp, tuple) and inp and inp[0] != MV_ASYNCARGS:
                m = "%x: first input not in MV_ASYNCARGS format: '%s'" % (inp,)
                raise ValueError(m)
            mv, mod, func, args, kw = inp
            mod = importlib.import_module(mod)
            func = getattr(mod, func)
            ret = async_call(func, args, kw, link)
            link.send(ret)
        except Exception as e:
            import traceback
            e = (MV_EXCEPTION, traceback.format_exc())
            link.send_shared(e)
            raise
        finally:
            link.disconnect()


class AsyncWorkerLink(object):
    def __init__(self, pool, index):
        self.pool = pool
        self.index = index

    def send(self, data, wait=1):
        self.pool.master_queue.put((self.index, data), block=wait)

    def receive(self, wait=1):
        ret = self.pool.worker_queues[self.index].get(block=wait)
        if isinstance(ret, tuple) and ret and ret[0] == MV_EXCEPTION:
            raise Exception(ret[1])
        return ret

    def send_shared(self, data, wait=1):
        self.pool.master_queue.put((0, data), block=wait)

    def disconnect(self, wait=1):
        self.pool.master_queue.put((self.index, None), block=wait)


class AsyncWorkerPool(object):
    def __init__(self, nr_parallel, worker_func):
        master_queue = Queue()
        self.master_queue = master_queue
        self.worker_queues = [master_queue] + [
                              Queue() for _ in range(nr_parallel)]
        worker_pids = []
        self.worker_pids = worker_pids
        append = worker_pids.append

        for i in range(nr_parallel):
            pid = fork()
            Random.atfork()
            CheapQueue.atfork()
            if not pid:
                try:
                    worker_link = AsyncWorkerLink(self, i+1)
                    worker_func(worker_link)
                finally:
                    try:
                        kill(getpid(), SIGKILL)
                    except:
                        pass
                    while 1:
                        print("PLEASE KILL ME")
                        sleep(1)
            append(pid)

    def kill(self):
        for pid in self.worker_pids:
            try:
                kill(pid, SIGKILL)
                waitpid(pid, 0)
            except OSError as e:
                if e.errno != ESRCH:
                    raise

    def send(self, worker, data):
        if not worker:
            m = "Controller attempt to write to master link"
            raise AssertionError(m)
        self.worker_queues[worker].put(data)

    def receive(self, wait=1):
        try:
            val = self.master_queue.get(block=wait)
        except Empty:
            val = None
        return val


class AsyncChannel(object):
    def __init__(self, controller):
        self.controller = controller
        self.channel_no = controller.get_channel()

    def send(self, data):
        return self.controller.send(self.channel_no, data)

    def receive(self, wait=1):
        data = self.controller.receive(self.channel_no, wait=wait)
        if isinstance(data, tuple) and data and data[0] == MV_EXCEPTION:
            raise Exception(data[1])
        return data


class AsyncFunc(object):
    def __init__(self, controller, func, args, kw):
        self.controller = controller
        self.func = func
        self.args = args
        self.kw = kw

    def __call__(self, *args, **kw):
        call_kw = dict(self.kw)
        call_kw.update(kw)
        call_args = self.args + args
        call_func = self.func
        controller = self.controller
        async_args = (MV_ASYNCARGS,
                      call_func.__module__, call_func.__name__,
                      call_args, call_kw)
        channel = AsyncChannel(controller)
        controller.submit(channel.channel_no, async_args)
        return channel


class AsyncController(object):
    serial = 0
    parallel = 0
    channel_queue = None
    shared_queue = None

    def __new__(cls, *args, **kw):
        parallel = int(kw.get('parallel', 2))
        self = object.__new__(cls)
        master_link = AsyncWorkerPool(parallel, async_worker)
        self.master_link = master_link
        self.idle_workers = set(range(1, parallel + 1))
        self.worker_to_channel = [0] + [None] * (parallel)
        self.channel_to_worker = {0: 0}
        self.pending = deque()
        self.channels = {0: deque()}
        self.parallel = parallel
        return self

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        master_link = self.master_link
        for i in range(1, self.parallel + 1):
            master_link.send(i, None)
        sleep(0.3)
        self.master_link.kill()

    def get_channel(self):
        channel = self.serial + 1
        self.serial = channel
        return channel

    def process(self, wait=0):
        master_link = self.master_link
        idle_workers = self.idle_workers
        pending = self.pending
        channel_to_worker = self.channel_to_worker
        worker_to_channel = self.worker_to_channel
        channels = self.channels

        _wait = wait
        while 1:
            blocked = []
            while pending:
                channel, data = pending.pop()
                if channel in channel_to_worker:
                    worker = channel_to_worker[channel]
                    master_link.send(worker, data)
                elif not idle_workers:
                    blocked.append((channel, data))
                else:
                    worker = idle_workers.pop()
                    channel_to_worker[channel] = worker
                    worker_to_channel[worker] = channel
                    master_link.send(worker, data)
            for b in blocked:
                pending.appendleft(b)

            data = master_link.receive(wait=_wait)
            if data is None:
                break
            _wait = 0

            worker, data = data
            channel = worker_to_channel[worker]
            if channel is None:
                continue

            if data is None:
                if worker > 0:
                    worker_to_channel[worker] = None
                else:
                    m = "Attempt to disconnect master link"
                    raise AssertionError(m)
                if channel > 0:
                    del channel_to_worker[channel]
                else:
                    m = "Attempt to close master channel"
                    raise AssertionError(m)

                idle_workers.add(worker)
            else:
                channels[channel].appendleft(data)

    def send(self, channel_no, data):
        channel_to_worker = self.channel_to_worker
        if channel_no not in channel_to_worker:
            return
        worker = channel_to_worker[channel_no]
        self.master_link.send(worker, data)

    def receive(self, channel_no, wait=1):
        channels = self.channels
        if channel_no not in channels:
            return None

        self.process(wait=0)
        while 1:
            if not channels[channel_no]:
                if (channel_no is not None and
                    channel_no not in self.channel_to_worker):
                    del channels[channel_no]
                    return None

                if not wait:
                    return None

                self.process(wait=1)
            else:
                val = channels[channel_no].pop()
                return val

    def receive_shared(self, wait=1):
        val = self.receive(0, wait=wait)
        if isinstance(val, tuple) and val and val[0] == MV_EXCEPTION:
            raise Exception(val[1])
        return val

    def submit(self, channel_no, async_args):
        channels = self.channels
        if channel_no in channels:
            m = "Channel already in use"
            raise ValueError(m)
        channels[channel_no] = deque()
        self.pending.appendleft((channel_no, async_args))
        if self.parallel <= 0:
            async_worker
        self.process(wait=0)

    def make_async(self, func, *args, **kw):
        return AsyncFunc(self, func, args, kw)
