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
# A plugin for parsing the IDT from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return IDTSet(vol)

def getFields():
    return IDT().get_field_keys()


class IDTSet(memobj.MemObjectSet):
    '''
    Parses IDT entries from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['string'] = ['module', 'section']    
        return defs
    
    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's IDT plugin.
        '''
        import volatility.plugins.malware.idt as idt
        import volatility.utils as utils
        
        addr_space = utils.load_as(self.vol.config)

        if self.is_valid_profile(addr_space.profile):
            vol_idt = idt.IDT(self.vol.config)
            for n, entry, addr, module in vol_idt.calculate():
                idt_entry = IDT(n, entry, addr, module, vol_idt.get_section_name(module, addr) if module else '', str(hex(int(addr))))
                yield idt_entry
        else:
            import sys
            sys.stderr.write("idt plugin does not support %s\n" % self.vol.config.get_value('profile'))
                

    def get_child(self):
        return IDT()


    def get_unique_id(self, idt):
        return (idt.fields['cpu_number'], idt.fields['the_index'], idt.fields['selector'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: (x.fields['cpu_number'], int(x.fields['the_index'], 16)))
        return elems


        
class IDT(memobj.MemObject):

    def __init__(self, n=None, entry=None, addr=None, module=None, section=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        del(self.fields['offset'])

        # The parent is IDT. The grand-parent is _KPCR.
        cpu_number = entry.obj_parent.obj_parent.ProcessorBlock.Number if entry else None

        self.fields['cpu_number'] = str(cpu_number)
        self.fields['the_index'] = str(hex(n)) if n else '0x0'
        self.fields['selector'] = str(hex(int(entry.Selector)))  if entry else ''
        self.fields['module'] = str(module.BaseDllName or '') if module else 'UNKNOWN'
        self.fields['section'] = str(section)
    

        
