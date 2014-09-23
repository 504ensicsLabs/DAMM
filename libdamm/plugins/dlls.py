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
# A plugin for parsing DLLs from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return DLLSet(vol)

def getFields():
    return DLL().get_field_keys()


class DLLSet(memobj.MemObjectSet):
    '''
    Parses DLLs from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_id']    
        defs['string'] = ['process_name', 'dll_mapped_path', 'load_full_dll_name', 'init_full_dll_name', 'mem_full_dll_name']
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's ldrmodules and dlllist plugins.
        '''
        from volatility.plugins.malware.malfind import LdrModules as LdrModules
        import volatility.obj as obj
        
        vol_ldrmodules = LdrModules(self.vol.config)    
        for task in vol_ldrmodules.calculate():
            # Build a dictionary for all three PEB lists where the
            # keys are base address and module objects are the values.
            inloadorder = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
            ininitorder = dict((mod.DllBase.v(), mod) for mod in task.get_init_modules())
            inmemorder = dict((mod.DllBase.v(), mod) for mod in task.get_mem_modules())

            # Build a similar dictionary for the mapped files.
            mapped_files = {}
            for vad, address_space in task.get_vads(vad_filter=task._mapped_file_filter):
                # Note this is a lot faster than acquiring the full
                # vad region and then checking the first two bytes.
                if obj.Object("_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space).e_magic != 0x5A4D:
                    continue

                mapped_files[int(vad.Start)] = str(vad.FileObject.FileName or "")

            # For each base address with a mapped file, print info on
            # the other PEB lists to spot discrepancies.
            for base in mapped_files.keys():
                # Does the base address exist in the PEB DLL lists?
                load_mod = inloadorder.get(base, None)
                init_mod = ininitorder.get(base, None)
                mem_mod = inmemorder.get(base, None)
    
                yield DLL(task, base, load_mod, init_mod, mem_mod, mapped_files, 0)


            
    def get_child(self):
        return DLL()


    def sort_elems(self, elems):
        elems.sort(key=lambda x: (int(x.fields['process_id']), int(x.fields['dll_base'], 16)))
        return elems

        
class DLL(memobj.MemObject):

    def __init__(self, task=None, base=None, load_mod=None, init_mod=None, mem_mod=None, mapped_files=None, offset=None):
        memobj.MemObject.__init__(self, offset)
        
        del(self.fields['offset'])
        self.fields['process_id'] = str(int(task.UniqueProcessId)) if task else None
        self.fields['process_name'] = str(task.ImageFileName) if task else None
        self.fields['dll_base'] = "{0:#x}".format(base) if base else None
        self.fields['load_count'] = str(hex(load_mod.LoadCount)).rstrip('L') if load_mod else ''
        self.fields['size_of_image'] = str(load_mod.SizeOfImage) if load_mod else ''
        self.fields['dll_in_load'] = str(not load_mod is None)
        self.fields['dll_in_init'] = str(not init_mod is None)
        self.fields['dll_in_mem'] = str(not mem_mod is None)
        self.fields['dll_mapped_path'] = str(mapped_files[base]) if mapped_files else ''
        self.fields['load_full_dll_name'] = str(load_mod.FullDllName) if load_mod else ''
        self.fields['init_full_dll_name'] = str(init_mod.FullDllName) if init_mod else ''
        self.fields['mem_full_dll_name'] = str(mem_mod.FullDllName) if mem_mod else '' 
                            
        