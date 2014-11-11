from LTTngAnalyzes.sched import Sched
from LTTngAnalyzes.statedump import Statedump
from LTTngAnalyzes.syscalls import Syscalls


class State():
    def __init__(self):
        self.cpus = {}
        self.tids = {}
        self.disks = {}
        self.syscalls = {}
        self.sched = Sched(self.cpus, self.tids)
        self.syscall = Syscalls(self.cpus, self.tids, self.syscalls)
        self.statedump = Statedump(self.tids, self.disks)
