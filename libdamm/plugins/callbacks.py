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
# A plugin for parsing callbacks from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return CallbackSet(vol)

def getFields():
    return Callback().get_field_keys()


class CallbackSet(memobj.MemObjectSet):
    '''
    Parses callbacks from Windows memory dumps
    '''

    @staticmethod
    def get_field_typedefs():
        defs = {}
        defs['string'] = ['type', 'module', 'detail']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)


    def get_alloc(self, addr_space):
        '''
        Mimics volatility's PPP plugin.
        '''
        import volatility.plugins.malware.callbacks as callbacks
        import volatility.win32.tasks as tasks

        # for conn in connections.Connections(self.vol.config).calculate():
        vol_callback = callbacks.Callbacks(self.vol.config)
        for (sym, cb, detail), mods, mod_addrs in vol_callback.calculate():
            module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(cb))
            yield Callback(module, sym, cb, detail, 0)


    def get_child(self):
        return Callback()


class Callback(memobj.MemObject):

    def __init__(self, module=None, sym=None, cb=None, detail=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        del(self.fields['offset'])
        self.fields['type'] = str(sym) if sym else ''
        self.fields['callback'] = str(hex(int(cb))) if cb else ''
        self.fields['module'] = str(module.BaseDllName or module.FullDllName) if module else 'UNKNOWN'      
        self.fields['detail'] = str(detail or "-") if detail else ''
