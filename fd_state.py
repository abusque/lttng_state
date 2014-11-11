from collections import OrderedDict
from LTTngAnalyzes.common import FDType
from LTTngAnalyzes.state import State
from LTTngAnalyzes.syscalls import Syscalls


class FDState():
    def __init__(self, traces):
        self.traces = traces
        self.state = State()

        self.fd_events = []
        self.pid_metadata = {}

    def run(self):
        for event in self.traces.events:
            self.process_event(event)

    def process_event(self, event):
        if event.name == 'sched_switch':
            self.state.sched.switch(event)
        elif (event.name.startswith('sys_') or
              event.name.startswith('syscall_entry_')):
            self.state.syscall.entry(event)
        elif (event.name == 'exit_syscall' or
              event.name.startswith('syscall_exit_')):
            self.handle_syscall_exit(event)
        elif event.name == 'sched_process_fork':
            self.state.sched.process_fork(event)
        elif event.name == 'lttng_statedump_process_state':
            self.state.statedump.process_state(event)
        elif event.name == 'lttng_statedump_file_descriptor':
            self.state.statedump.file_descriptor(event)

    def handle_syscall_exit(self, event, started=1):
        cpu_id = event['cpu_id']
        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]
        if cpu.current_tid == -1:
            return

        current_syscall = self.state.tids[cpu.current_tid].current_syscall
        if len(current_syscall.keys()) == 0:
            return

        name = current_syscall['name']
        if name in Syscalls.OPEN_SYSCALLS or\
           name in Syscalls.CLOSE_SYSCALLS or\
           name in Syscalls.READ_SYSCALLS or\
           name in Syscalls.WRITE_SYSCALLS:
            self.log_fd_event(event, current_syscall)

        self.state.syscall.exit(event, started)

    def log_fd_event(self, exit_event, entry):
        name = entry['name']
        filename = entry['filename']
        if filename is None:
            return

        duration_ns = (exit_event.timestamp - entry['start'])
        ret = exit_event['ret']
        tid = self.state.cpus[exit_event['cpu_id']].current_tid
        comm = self.state.tids[tid].comm
        pid = self.state.tids[tid].pid
        if pid == -1:
            pid = tid

        self.track_thread(tid, pid, comm)

        fd = None
        fd_in = None
        fd_out = None

        if 'fd' in entry.keys():
            fd = entry['fd'].fd
        elif 'fd_in' in entry.keys():
            fd_in = entry['fd_in'].fd
            fd_out = entry['fd_out'].fd

        if fd:
            self.track_fd(fd, filename, tid, pid, entry)
        elif fd_in and fd_out:
            self.track_fd(fd_in, filename, tid, pid, entry)
            self.track_fd(fd_out, filename, tid, pid, entry)

        category = Syscalls.get_syscall_category(name)

        fd_event = {'ts_start': entry['start'],
                    'duration': duration_ns,
                    'tid': tid,
                    'pid': pid,
                    'category': category}

        if fd is not None:
            fd_event['fd'] = fd
        elif fd_in is not None and fd_out is not None:
            fd_event['fd_in'] = fd_in
            fd_event['fd_out'] = fd_out

        if ret < 0:
            fd_event['errno'] = -ret
        else:
            if name in ['sys_splice', 'sys_sendfile64']:
                fd_event['read'] = ret
                fd_event['write'] = ret
            elif name in Syscalls.READ_SYSCALLS:
                fd_event['read'] = ret
            elif name in Syscalls.WRITE_SYSCALLS:
                fd_event['write'] = ret

        self.fd_events.append(fd_event)

    def track_thread(self, tid, pid, comm):
        # Dealing with plain old process
        if pid == tid:
            if pid not in self.pid_metadata:
                self.pid_metadata[pid] = {
                    'pname': comm,
                    'fds': {},
                    'threads': {}
                }
            else:
                if self.pid_metadata[pid]['pname'] != comm:
                    self.pid_metadata[pid]['pname'] = comm
        # Dealing with a thread
        else:
            if pid not in self.pid_metadata:
                self.pid_metadata[pid] = {
                    'pname': 'unknown',
                    'fds': {},
                    'threads': {}
                }

            tid_str = str(tid)
            if tid_str not in self.pid_metadata[pid]['threads']:
                self.pid_metadata[pid]['threads'][tid_str] = {
                    'pname': comm
                }
            else:
                if self.pid_metadata[pid]['threads'][tid_str]['pname'] \
                        != comm:
                    self.pid_metadata[pid]['threads'][tid_str]['pname'] = comm

    def track_fd(self, fd, filename, tid, pid, entry):
        fd_str = str(fd)
        fdtype = FDType.unknown

        if fd in self.state.tids[tid].fds:
            fdtype = self.state.tids[tid].fds[fd].fdtype

        fd_metadata = {}
        fd_metadata['filename'] = filename
        fd_metadata['fdtype'] = fdtype

        if str(fd) not in self.pid_metadata[pid]['fds']:
            fds = self.pid_metadata[pid]['fds']
            fds[fd_str] = OrderedDict()
            fds[fd_str][str(entry['start'])] = fd_metadata
        else:
            chrono_fd = self.pid_metadata[pid]['fds'][fd_str]
            last_ts = next(reversed(chrono_fd))
            if filename != chrono_fd[last_ts]['filename']:
                chrono_fd[str(entry['start'])] = fd_metadata
