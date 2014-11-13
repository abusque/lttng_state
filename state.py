from lttng_state.sched import Sched
from lttng_state.statedump import Statedump
from lttng_state.syscalls import Syscalls


class State():
    def __init__(self):
        self.cpus = {}
        self.tids = {}
        self.disks = {}
        self.syscalls = {}
        self.sched = Sched(self.cpus, self.tids)
        self.syscall = Syscalls(self.cpus, self.tids, self.syscalls)
        self.statedump = Statedump(self.tids, self.disks)
