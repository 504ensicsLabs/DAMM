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
# A plugin for parsing process privileges from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return PrivilegeSet(vol)

def getFields():
    return Privilege().get_field_keys()


class PrivilegeSet(memobj.MemObjectSet):
    '''
    Parses privileges from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_id']
        defs['string'] = ['filename', 'privilege', 'description']    
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's privileges plugin.
        '''
        import volatility.plugins.privileges as privileges
        import volatility.plugins.privileges as privm

        for task in privileges.Privs(self.vol.config).calculate():
            for value, present, enabled, default in task.get_token().privileges():
                try:
                    name, desc = privm.PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue 

                yield Privilege(value, task, desc, name, present, enabled, default, 0)

    
    def get_child(self):
        return Privilege()


    def get_unique_id(self, priv):
        return (priv.fields['process_id'], priv.fields['filename'], priv.fields['value'], priv.fields['privilege'], priv.fields['description'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: (int(x.fields['process_id']), x.fields['privilege'].lower()))
        return elems



class Privilege(memobj.MemObject):

    def __init__(self, value=None, task=None, description=None, name=None, present=None, enabled=None, default=None, offset=None):
        memobj.MemObject.__init__(self, offset)
                

        del(self.fields['offset'])        
        self.fields['process_id'] = str(int(task.UniqueProcessId)) if task else ''
        self.fields['filename'] = str(task.ImageFileName) if task else ''
        self.fields['value'] = str(int(value)) if value else ''
        self.fields['privilege'] = str(name) if name else ''
        self.fields['present'] = str(present) if present else ''
        self.fields['enabled'] = str(enabled) if enabled else ''
        self.fields['the_default'] = str(default) if default else ''
        self.fields['description'] = str(description) if description else ''
