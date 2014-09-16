# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common

class linux_pslist(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

    def virtual_process_from_physical_offset(self, offset):
        pspace = utils.load_as(self._config, astype = 'physical')
        vspace = utils.load_as(self._config)
        task = obj.Object("task_struct", vm = pspace, offset = offset)
        parent = obj.Object("task_struct", vm = vspace, offset = task.parent)
        
        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child
        
        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
                yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                yield task

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("Uid", "15"),
                                  ("Gid", "6"),
                                  ("DTB", "[addrpad]"),
                                  ("Start Time", "")])
        for task in data:
            if task.mm.pgd == None:
                dtb = task.mm.pgd
            else:
                dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd
            self.table_row(outfd, task.obj_offset,
                                  task.comm,
                                  str(task.pid),
                                  str(task.uid) if task.uid else "-",
                                  str(task.gid) if task.gid else "-",
                                  dtb,
                                  task.get_task_start_time())

class linux_memmap(linux_pslist):
    """Dumps the memory map for linux tasks"""

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Task", "16"),
                                  ("Pid", "8"),
                                  ("Virtual", "[addrpad]"),
                                  ("Physical", "[addrpad]"),
                                  ("Size", "[addr]")])

        for task in data:
            task_space = task.get_process_address_space()

            pagedata = task_space.get_available_pages()
            if pagedata:
                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        self.table_row(outfd, task.comm, task.pid, p[0], pa, p[1])
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
            else:
                outfd.write("Unable to read pages for {0} pid {1}.\n".format(task.comm, task.pid))

