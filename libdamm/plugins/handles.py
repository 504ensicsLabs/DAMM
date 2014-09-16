# DAMM 
# Copyright (c) 2013 504ENSICS Labs
#
# This file is part of DAMM.
#
# DAMM is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# DAMM is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#

#
# A plugin for parsing handles from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return HandleSet(vol)

def getFields():
    return Handle().get_field_keys()


class HandleSet(memobj.MemObjectSet):
    '''
    Parses handles from Windows memory dumps.
    '''

    @staticmethod
    def get_field_typedefs():
        defs = {}
        defs['pid'] = ['pid']
        defs['string'] = ['name', 'object_type']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)


    def get_alloc(self, addr_space):
        '''
        Mimics volatility's handles plugin.
        '''
        import volatility.plugins.handles as handles

        for handle_info in handles.Handles(self.vol.config).calculate():
            yield Handle(handle_info, self.get_offset(handle_info[1].Body))


    def get_child(self):
        return Handle()

    def sort_elems(self, elems):
        elems.sort(key=lambda x: (int(x.fields['pid']), x.fields['object_type'].lower(), x.fields['name'].lower()))
        return elems



class Handle(memobj.MemObject):

    def __init__(self, handle_info=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        self.fields['pid'] = str(handle_info[0]) if handle_info else None
        self.fields['handle_value'] = str(hex(handle_info[1].HandleValue).rstrip("L")) if handle_info else None
        self.fields['granted_access'] = str(hex(handle_info[1].GrantedAccess).rstrip("L")) if handle_info else None
        self.fields['object_type'] = str(handle_info[2]) if handle_info else None
        self.fields['name'] = str(handle_info[3]) if handle_info else None
