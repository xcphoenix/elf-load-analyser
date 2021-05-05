# code from "https://gist.github.com/scottt/8f7be45708fbea8b7189#file-bin-true-ld-so-processing-log-L435

import gdb
import pprint
import difflib


class CatchSyscallState:
    def __init__(self):
        self.stop_count = 0
        self.do_continue = False  # execute 'continue' in main loop
        self.maps_on_last_entry = None

    def stop_handler(self, event):
        if isinstance(event, gdb.BreakpointEvent):
            return

        # every syscall stops once on entry, once on return
        if self.stop_count % 2 == 0:
            self.syscall_entry_handler(event)
        else:
            self.syscall_exit_handler(event)
        self.stop_count += 1
        self.do_continue = True

    def syscall_entry_handler(self, event):
        pid = event.inferior_thread.ptid[0]
        self.maps_on_last_entry = open('/proc/%d/maps' % (pid,)).read()

    def syscall_exit_handler(self, event):
        pid = event.inferior_thread.ptid[0]
        t = open('/proc/%d/maps' % (pid,)).read()
        prev = self.maps_on_last_entry.split('\n')
        current = t.split('\n')
        # for l in difflib.unified_diff(prev, current, lineterm=''):
        for line in difflib.context_diff(prev, current, n=30, lineterm=''):
            print(line)

        gdb.execute('backtrace')

    def exec_continue(self):
        if not self.do_continue:
            return

        self.do_continue = False
        gdb.execute('continue')


class MainBreakpoint(gdb.Breakpoint):
    def stop(self):
        gdb.write('\n\n\nmain() called\n\n\n')
        return False


gdb.execute('set non-stop 1')
gdb.execute('file /usr/bin/whoami')
gdb.execute('catch syscall mmap mprotect munmap')
# gdb.execute('commands 1\nsilent\nend\n')
s = CatchSyscallState()
gdb.events.stop.connect(s.stop_handler)
b = MainBreakpoint('main')
gdb.execute('run')
while s.do_continue:
    s.exec_continue()
gdb.execute('quit')
