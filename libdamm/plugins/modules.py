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
# A plugin for parsing modules from Windows memory dumps.
#

import volatility.win32.modules as modules
import volatility.plugins.modscan as modscan
import libdamm.memory_object as memobj


def getPluginObject(vol):
    return ModuleSet(vol)

def getFields():
    return Module().get_field_keys()

    
class ModuleSet(memobj.MemObjectSet):
    '''
    Manages sets of Windows modules parsed from memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['string'] = ['base_dll_name', 'full_dll_name']
        return defs    
 
            
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        
    def get_alloc(self, addr_space):
        '''
        # Mimic Volatility modules plugin
        '''
        for module in modules.lsmod(addr_space):
            yield Module(module, True, self.get_offset(module, True))

            
    def get_scan(self):
        '''
        # Mimic Volatility modscan plugin
        '''
        for mod in modscan.ModScan(self.vol.config).calculate():
            yield Module(mod, False, self.get_offset(mod))

                          
    def get_child(self):
        return Module()


    def get_unique_id(self, module):
        return (module.fields['offset'], module.fields['base_dll_name'], module.fields['size_of_image'], module.fields['full_dll_name'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['offset'], 16))
        return elems

   

class Module(memobj.MemObject):


    def __init__(self, mod=None, allocated='', offset=None):
        memobj.MemObject.__init__(self, offset)

        self.fields['base_dll_name'] = str(mod.BaseDllName) if mod else None
        self.fields['dll_base'] = str(hex(mod.DllBase)).rstrip('L') if mod else None
        self.fields['size_of_image'] = str(hex(mod.SizeOfImage)).rstrip('L') if mod else None
        self.fields['full_dll_name'] = str(mod.FullDllName) if mod else None
        self.fields['allocated'] = str(allocated)
