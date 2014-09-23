# DAMM 
# Copyright (c) 2013 504ENSICS Labs
#
# This file is part of DAMM.
#
# DAMM is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# DAMM is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with DAMM.  If not, see <http://www.gnu.org/licenses/>.
#

#
# A plugin for parsing processes from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return ProcessSet(vol)

def getFields():
    return Process().get_field_keys()


class ProcessSet(memobj.MemObjectSet):
    '''
    Manages sets of Windows processes parsed from memory dumps.
    '''
    @staticmethod
    def get_field_typedefs():
        defs = {}
        defs['pid'] = ['pid', 'ppid']
        defs['time'] = ['create_time', 'exit_time']
        defs['string'] = ['name']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        self.vol = vol


    def get_all(self):
        '''
        Mimics Volatility's psxview, pslist, psscan, cmdline plugins
        '''
        import volatility.plugins.malware.psxview as psxview

        for offset, process, ps_sources in psxview.PsXview(self.vol.config).calculate():
            yield Process(process, ps_sources, offset)


    def get_child(self):
        return Process()


    def get_unique_id(self, proc):
        return (proc.fields['pid'], proc.fields['name'], proc.fields['ppid'], proc.fields['create_time'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['pid']))
        return elems


class Process(memobj.MemObject):

    def __init__(self, task=None, xview=None, offset=None):

        # Must init superclass
        off = str(hex(offset)).rstrip('L') if offset else None
        memobj.MemObject.__init__(self, off)

        # These are all of the process fields we know about
        self.fields['name'] = str(task.ImageFileName) if task else ''
        self.fields['pid'] = str(task.UniqueProcessId).rstrip('L') if task else ''
        self.fields['ppid'] = str(task.InheritedFromUniqueProcessId).rstrip('L') if task else ''
        self.fields['prio'] = str(task.Pcb.BasePriority) if task else ''
        self.fields['image_path_name'] = str(task.Peb.ProcessParameters.ImagePathName) if task else ''
        
        self.fields['create_time'] = str(task.CreateTime or '') if task else ''
        self.fields['exit_time'] = str(task.ExitTime or '') if task else ''
        self.fields['threads'] = str(task.ActiveThreads).rstrip('L') if task else ''
        self.fields['session_id'] = str(task.SessionId).rstrip('L') if task else ''
        self.fields['handles'] = str(task.ObjectTable.HandleCount).rstrip('L') if task else ''
        self.fields['is_wow64'] = str(task.IsWow64) if task else ''

        self.fields['pslist'] = str(xview['pslist'].has_key(offset)) if xview else ''
        self.fields['psscan'] = str(xview['psscan'].has_key(offset)) if xview else ''
        self.fields['thrdproc'] = str(xview['thrdproc'].has_key(offset)) if xview else ''
        self.fields['pspcid'] = str(xview['pspcid'].has_key(offset)) if xview else ''
        self.fields['csrss'] = str(xview['csrss'].has_key(offset)) if xview else ''
        self.fields['session'] = str(xview['session'].has_key(offset)) if xview else ''
        self.fields['deskthrd'] = str(xview['deskthrd'].has_key(offset)) if xview else ''

        self.fields['command_line'] = str(task.Peb.ProcessParameters.CommandLine) if task else ''
