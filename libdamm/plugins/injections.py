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
# A plugin for finding injected code in Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return InjectionSet(vol)

def getFields():
    return Injection().get_field_keys()


class InjectionSet(memobj.MemObjectSet):
    '''
    Manages sets possible malware sightings in memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['task_unique_proces_id']
        defs['string'] = ['task_image_file_name']
        return defs

                
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        
    def get_alloc(self, addr_space):
        '''
        Mimics the Volatility malfind plugin
        '''
        import volatility.plugins.malware.malfind as malfind
        import volatility.utils as utils

        mfind = malfind.Malfind(self.vol.config)
        for task in mfind.calculate():  
            for vad, address_space in task.get_vads(vad_filter=task._injection_filter):
                if mfind._is_vad_empty(vad, address_space):
                    continue
                content = address_space.zread(vad.Start, 16)    
                content = "{0}".format("\n".join(
                    ["{0:<48}  {1}".format(h, ''.join(c))
                    for o, h, c in utils.Hexdump(content)
                    ]))
                offset = "{0:#x}".format(vad.Start)
                yield Injection(task, vad, offset, content)

                
    def get_child(self):
        return Injection()


    def sort_elems(self, elems):
        elems.sort(key=lambda x: (int(x.fields['task_unique_proces_id']), int(x.fields['address'], 16)))
        return elems


class Injection(memobj.MemObject):

    def __init__(self, task=None, vad=None, offset=None, content=None):
    
        import volatility.plugins.vadinfo as vadinfo
        memobj.MemObject.__init__(self, offset)

        self.fields['task_image_file_name'] = str(task.ImageFileName) if task else None
        self.fields['task_unique_proces_id'] = str(task.UniqueProcessId) if task else None
        self.fields['address'] = self.fields['offset']
        del(self.fields['offset'])
        #self.fields['vad_start'] = str("{0:#x}".format(vad.Start)) if vad else None
        self.fields['vad_tag'] = str(vad.Tag) if vad else None
        self.fields['protections'] = str(vadinfo.PROTECT_FLAGS.get(vad.u.VadFlags.Protection.v(), "")) if vad else None
        self.fields['content'] = content if content else None
        self.fields['flags'] = str(vad.u.VadFlags) if vad else None
                