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
# A plugin for finding API hooks in Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return APIHookSet(vol)

def getFields():
    return APIHook().get_field_keys()


class APIHookSet(memobj.MemObjectSet):
    '''
    Finds API hooks Windows in memory dumps
    '''    
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_unique_process_id']
        defs['string'] = ['process_image_file_name', 'module_base_dll_name', 'hook_detail', 'hook_module']
        return defs
           
        
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

    def get_alloc(self, addr_space):
        
        import volatility.plugins.malware.apihooks as apihooks
        
        for hook in apihooks.ApiHooks(self.vol.config).calculate():
            yield APIHook(hook, str(hex(hook[2].hook_address)).rstrip('L'))


    def get_child(self):
        return APIHook()        
     
     
    def get_unique_id(self, hook):
        return (hook.fields['process_unique_process_id'], hook.fields['process_image_file_name'], hook.fields['module_base_dll_name'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: (x.fields['process_unique_process_id'], x.fields['module_base_dll_name'].lower()))
        return elems
        

            
class APIHook(memobj.MemObject):

    def __init__(self, hook_info=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        process = hook_info[0] if hook_info else ''
        module = hook_info[1] if hook_info else ''
        hook = hook_info[2] if hook_info else '' 

        self.fields['hook_mode'] = str(hook.Mode) if hook else ''
        self.fields['hook_type'] = str(hook.Type) if hook else ''
        self.fields['process_unique_process_id'] = str(process.UniqueProcessId) if process else ''
        self.fields['process_image_file_name'] = str(process.ImageFileName) if process else ''
        self.fields['module_base_dll_name'] = str((module.BaseDllName or '') or ntpath.basename(str(module.FullDllName))) if module else ''
        self.fields['module_dll_base'] = str(hex(module.DllBase)).rstrip('L') if module else ''
        self.fields['module_dll_base_end'] = str(hex(module.DllBase + module.SizeOfImage)).rstrip('L')  if module else ''
        self.fields['hook_detail'] = str(hook.Detail) if hook else ''
        self.fields['hook_address'] = str(hex(hook.hook_address)).rstrip('L') if hook else ''
        self.fields['hook_module'] = str(hook.HookModule) if hook else ''
