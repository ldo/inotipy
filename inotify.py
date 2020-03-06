"""
Pure-Python binding for the Linux inotify(7) API using ctypes and
working with asyncio.
"""
#+
# Copyright 2018-2020 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import os
import enum
import ctypes as ct
import struct
from weakref import \
    ref as weak_ref, \
    WeakValueDictionary
import asyncio
import atexit

libc = ct.CDLL("libc.so.6", use_errno = True)

NAME_MAX = 255 # from <linux/limits.h>

class inotify_event(ct.Structure) :
    # from <sys/inotify.h>
    _fields_ = \
        [
            ("wd", ct.c_int),
            ("mask", ct.c_uint),
            ("cookie", ct.c_uint),
            ("len", ct.c_uint), # length of name, including trailing NULs, won’t exceed NAME_MAX
            # name follows
        ]
#end inotify_event

class IN :
    "definitions of flag bits that you will need."

    # from <bits/inotify.h>: flags for inotify_init1
    CLOEXEC = 0o2000000
    NONBLOCK = 0o0004000

    # from <sys/inotify.h>:

    # mask bits for INOTIFY_ADD_WATCH:
    ACCESS = 0x00000001
    MODIFY = 0x00000002
    ATTRIB = 0x00000004
    CLOSE_WRITE = 0x00000008
    CLOSE_NOWRITE = 0x00000010
    CLOSE = CLOSE_WRITE | CLOSE_NOWRITE
    OPEN = 0x00000020
    MOVED_FROM = 0x00000040
    MOVED_TO = 0x00000080
    MOVE = MOVED_FROM | MOVED_TO
    CREATE = 0x00000100
    DELETE = 0x00000200
    DELETE_SELF = 0x00000400
    MOVE_SELF = 0x00000800

    # events from kernel:
    UNMOUNT = 0x00002000
    Q_OVERFLOW = 0x00004000
    IGNORED = 0x00008000

    # special flags:
    ONLYDIR = 0x01000000
    DONT_FOLLOW = 0x02000000
    EXCL_UNLINK = 0x04000000
    MASK_ADD = 0x20000000
    ISDIR = 0x40000000
    ONESHOT = 0x80000000

    ALL_EVENTS = \
        (
            ACCESS
        |
            MODIFY
        |
            ATTRIB
        |
            CLOSE_WRITE
        |
            CLOSE_NOWRITE
        |
            OPEN
        |
            MOVED_FROM
        |
            MOVED_TO
        |
            CREATE
        |
            DELETE
        |
            DELETE_SELF
        |
            MOVE_SELF
        )

#end IN

@enum.unique
class EVENT_BIT(enum.IntEnum) :
    "names for single bits in mask; value is bit number."

    ACCESS = 0
    MODIFY = 1
    ATTRIB = 2
    CLOSE_WRITE = 3
    CLOSE_NOWRITE = 4
    OPEN = 5
    MOVED_FROM = 6
    MOVED_TO = 7
    CREATE = 8
    DELETE = 9
    DELETE_SELF = 10
    MOVE_SELF = 11
    UNMOUNT = 13
    Q_OVERFLOW = 14
    IGNORED = 15

    ONLYDIR = 24
    DONT_FOLLOW = 25
    EXCL_UNLINK = 26
    MASK_ADD = 29
    ISDIR = 30
    ONESHOT = 31

    @property
    def mask(self) :
        "convert bit number to mask."
        return \
            1 << self.value
    #end mask

#end EVENT_BIT

#+
# Library prototypes
#-

libc.inotify_init.restype = ct.c_int
libc.inotify_init.argtypes = ()
libc.inotify_init1.restype = ct.c_int
libc.inotify_init1.argtypes = (ct.c_int,)
libc.inotify_add_watch.restype = ct.c_int
libc.inotify_add_watch.argtypes = (ct.c_int, ct.c_char_p, ct.c_uint)
libc.inotify_rm_watch.restype = ct.c_int
libc.inotify_rm_watch.argtypes = (ct.c_int, ct.c_int)

#+
# High-level stuff follows
#-

def decode_mask(mask) :
    mask_bits = []
    for i in range(32) :
        if 1 << i & mask != 0 :
            try :
                name = EVENT_BIT(i)
            except ValueError :
                name = "?%d" % i
            #end try
            mask_bits.append(name)
        #end if
    #end for
    return \
        mask_bits
#end decode_mask

class Watch :
    "represents a file path being watched. Do not create directly; get from Watcher.watch()."

    __slots__ = ("__weakref__", "_parent", "pathname", "mask", "wd") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, wd, _parent) :
        self = celf._instances.get((wd, _parent.fd))
        if self == None :
            self = super().__new__(celf)
            self.wd = wd
            self._parent = weak_ref(_parent)
            celf._instances[(wd, _parent.fd)] = self
        #end if
        # pathname, mask set by parent
        _parent._watches[wd] = self
        return \
            self
    #end __new__

    def __del__(self) :
        self.remove()
    #end __del__

    @property
    def valid(self) :
        "is this Watch object still valid. It can become invalid after a" \
        " remove() call, or after inotify sends an IN.IGNORED event for it."
        return \
            self._parent != None and self.wd != None
    #end valid

    def remove(self) :
        "removes itself from being watched. Do not try to use this Watch" \
        " object for anything else after making this call."
        if self.wd != None and self._parent != None :
            parent = self._parent()
            if parent != None :
                libc.inotify_rm_watch(parent.fd, self.wd) # ignoring any error
                parent._watches.pop(self.wd, None)
            #end if
            self.wd = None
        #end if
    #end remove

    def replace_mask(self, mask) :
        "lets you change the mask associated with this Watch."
        parent = self._parent()
        assert parent != None, "parent has gone away"
        wd = libc.inotify_add_watch(parent.fd, self.pathname.encode(), mask)
        if wd < 0 :
            errno = ct.get_errno()
            raise OSError(errno, os.strerror(errno))
        elif wd != self.wd :
            raise RuntimeError("inconsistency in watch descriptors")
        #end if
        self.mask = mask
    #end replace_mask

    def __repr__(self) :
        return \
            (
                "%s(%s, %#0.8x%s, %s:%d)"
            %
                (
                    type(self).__name__,
                    repr(self.pathname),
                    self.mask,
                    decode_mask(self.mask),
                    (lambda : "<orphaned>", lambda : self._parent().fd)
                        [self._parent != None and self._parent() != None](),
                    self.wd
                )
            )
    #end __repr__

#end Watch

class Event :
    "represents a watch event. Do not instantiate directly; get from Watcher.get()."

    __slots__ = ("watch", "mask", "cookie", "pathname") # to forestall typos

    def __init__(self, watch, mask, cookie, pathname) :
        self.watch = watch
        self.mask = mask
        self.cookie = cookie
        self.pathname = pathname
    #end __init

    def __repr__(self) :
        return \
            (
                "%s(%s, %#0.8x%s, %d, %s)"
            %
                (
                    type(self).__name__,
                    (lambda : None, lambda : self.watch.wd)[self.watch != None](),
                    self.mask,
                    decode_mask(self.mask),
                    self.cookie,
                    repr(self.pathname)
                )
            )
    #end __repr__

#end Event

@enum.unique
class STOP_ON(enum.Enum) :
    "set of conditions on which to raise StopAsyncIteration:\n" \
    "\n" \
    "    TIMEOUT - timeout has elapsed\n" \
    "\n" \
    "Otherwise None will be returned on timeout."
    TIMEOUT = 1
    #CLOSED = 2 # can I implement this?
#end STOP_ON

class Watcher :
    "a context for watching one or more files or directories. Do not instantiate directly;" \
    " use the create() method."

    __slots__ = \
        ( # to forestall typos
            "__weakref__",
            "fd",
            "_watches",
            "_loop",
            "_reader_count",
            "_awaiting",
            "_notifs",
        )

    _instances = WeakValueDictionary()

    def __new__(celf, fd) :
        self = celf._instances.get(fd)
        if self == None :
            self = super().__new__(celf)
            self.fd = fd
            self._loop = None # to begin with
            self._watches = {}
            self._reader_count = 0
            self._awaiting = []
            self._notifs = []
            celf._instances[fd] = self
        #end if
        return \
            self
    #end __new__

    def _add_remove_watch(self, add) :
        loop = self._loop()
        if add :
            assert loop != None, "loop has gone away"
            loop.add_reader(self.fd, self._callback)
        else :
            if loop != None :
                loop.remove_reader(self.fd)
            #end if
        #end if
    #end _add_remove_watch

    @classmethod
    def create(celf, flags = 0, loop = None) :
        "creates a new Watcher for collecting filesystem notifications. loop is the" \
        " asyncio event loop into which to install reader callbacks; the default" \
        " loop is used if this not specified."
        if loop == None :
            loop = asyncio.get_event_loop()
        #end if
        fd = libc.inotify_init1(flags)
        if fd < 0 :
            errno = ct.get_errno()
            raise OSError(errno, os.strerror(errno))
        #end if
        result = celf(fd)
        if result._loop == None :
            result._loop = weak_ref(loop)
        elif result._loop() != loop :
            raise RuntimeError("watcher was not created on current event loop")
        #end if
        return \
            result
    #end create

    def watch(self, pathname, mask) :
        "adds a watch for the specified path, or replaces any previous" \
        " watch settings if there is already a watch on that path. Returns" \
        " the Watch object, either the same one as before or a new one for a" \
        " new path."
        wd = libc.inotify_add_watch(self.fd, pathname.encode(), mask)
        if wd < 0 :
            errno = ct.get_errno()
            raise OSError(errno, os.strerror(errno))
        #end if
        result = Watch(wd, self)
        result.pathname = pathname
        result.mask = mask
        return \
            result
    #end watch

    @property
    def watches(self) :
        "returns a list of currently-associated Watch objects."
        return \
            sorted(self._watches.values(), key = lambda w : w.pathname)
    #end watches

    def __del__(self) :
        if self.fd != None :
            self._add_remove_watch(False)
            os.close(self.fd)
        #end if
        self.fd = None
    #end __del__

    def fileno(self) :
        return \
            self.fd
    #end fileno

    def _callback(self) :
        # called by asyncio when there is a notification event to be read.
        fixed_size = ct.sizeof(inotify_event)
        buf = os.read(self.fd, fixed_size + NAME_MAX + 1)
        while len(buf) != 0 :
            assert len(buf) >= fixed_size, "truncated inotify message: expected %d bytes, got %d" % (fixed_size, len(buf))
            wd, mask, cookie, namelen = struct.unpack("@iIII", buf[:fixed_size])
            assert len(buf) >= fixed_size + namelen, "truncated rest of inotify message: expected %d bytes, got %d" % (fixed_size + namelen, len(buf))
            pathname = buf[fixed_size : fixed_size + namelen]
            buf = buf[fixed_size + namelen:]
            end = pathname.find(0)
            if end >= 0 :
                pathname = pathname[:end]
            #end if
            pathname = pathname.decode()
            if wd >= 0 :
                watch = self._watches[wd]
            else :
                assert mask & IN.Q_OVERFLOW != 0
                watch = None
            #end if
            if mask & IN.IGNORED != 0 :
                # watch is gone
                watch._parent = None # Watch object doesn’t need to remove itself
                self._watches.pop(wd)
            #end if
            wakeup = len(self._notifs) == 0
            self._notifs.append(Event(watch, mask, cookie, pathname))
            if wakeup and len(self._awaiting) != 0 :
                # wake up task at head of queue
                # also need to remove it from queue here, in case
                # anybody else is also waiting behind it and I have
                # additional incoming messages for them
                self._awaiting.pop(0).set_result(True)
            #end if
        #end while
    #end _callback

    async def get(self, timeout = None) :
        "waits for and returns the next available Event. Waits forever if" \
        " necessary if timeout is None; else it is the number of seconds" \
        " (fractions allowed) to wait; if no event becomes available during" \
        " that time, None is returned."

        awaiting = None

        def timedout(w_awaiting) :
            awaiting = w_awaiting()
            if awaiting != None and not awaiting.done() :
                awaiting.set_result(False)
            #end if
        #end timedout

    #begin get
        loop = self._loop()
        assert loop != None, "loop has gone away"
        while True :
            if len(self._notifs) != 0 :
                result = self._notifs.pop(0)
                break
            #end if
            awaiting = loop.create_future()
            timeout_task = None
            if timeout != None :
                if timeout <= 0 :
                    result = None
                    break
                #end if
                timeout_task = loop.call_later(timeout, timedout, weak_ref(awaiting))
            #end if
            self._awaiting.append(awaiting)
            if self._reader_count == 0 :
                self._add_remove_watch(True)
            #end if
            self._reader_count += 1
            got_one = await awaiting
            self._reader_count -= 1
            if self._reader_count == 0 :
                self._add_remove_watch(False)
            #end if
            if timeout_task != None :
                timeout_task.cancel()
            #end if
            try :
                self._awaiting.pop(self._awaiting.index(awaiting))
            except ValueError :
                pass
            #end try
            if not got_one :
                result = None
                break
            #end if
        #end while
        return \
            result
    #end get

    def iter_async(self, stop_on = None, timeout = None) :
        "wrapper around get() to allow use with an async-for statement." \
        " Lets you write\n" \
        "\n" \
        "    async for event in «watcher».iter_async(«stop_on», «timeout») :" \
        "        «process event»\n" \
        "    #end for\n" \
        "\n" \
        "to receive and process notifications in a loop. stop_on is an" \
        " optional set of STOP_ON.xxx values indicating the conditions" \
        " under which the iterator will raise StopAsyncIteration to" \
        " terminate the loop."
        if stop_on == None :
            stop_on = frozenset()
        elif (
                not isinstance(stop_on, (set, frozenset))
            or
                not all(isinstance(elt, STOP_ON) for elt in stop_on)
        ) :
            raise TypeError("stop_on must be None or set of STOP_ON")
        #end if
        return \
            _WatcherAiter(self, stop_on, timeout)
    #end iter_async

#end Watcher

class _WatcherAiter :
    # internal class for use by Watcher.iter_async (above).

    def __init__(self, watcher, stop_on, timeout) :
        self.watcher = watcher
        self.stop_on = stop_on
        self.timeout = timeout
    #end __init__

    def __aiter__(self) :
        # I’m my own iterator.
        return \
            self
    #end __aiter__

    async def __anext__(self) :
        result = await self.watcher.get(timeout = self.timeout)
        if result == None and STOP_ON.TIMEOUT in self.stop_on :
            raise StopAsyncIteration("Watcher.iter_async terminating")
        #end if
        return \
            result
    #end __anext__

#end _WatcherAiter

#+
# Cleanup
#-

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for cls in Watch, Watcher :
        delattr(cls, "__del__")
    #end for
#end _atexit
atexit.register(_atexit)
del _atexit
