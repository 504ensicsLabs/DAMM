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
# A plugin for parsing mutants from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return MutantSet(vol)

def getFields():
    return Mutant().get_field_keys()


class MutantSet(memobj.MemObjectSet):
    '''
    Parses mutants from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_id']
        defs['string'] = ['mutant_name']    
        defs['tid'] = ['thread_id']
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
            
    def get_scan(self):
        '''
        Mimics volatility's mutantscan plugin.
        '''
        from volatility.plugins.filescan import MutantScan as MutantScan
        
        for mutant in MutantScan(self.vol.config).calculate():
            yield Mutant(mutant, str(hex(mutant.obj_offset)).rstrip('L'))


    def get_child(self):
        return Mutant()


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['offset'], 16))
        return elems

        
class Mutant(memobj.MemObject):

    def __init__(self, mutant=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        tid = ''
        pid = ''
        header = None
        if mutant:    
            header = mutant.get_object_header()
            if mutant.OwnerThread.is_valid():
                thread = mutant.OwnerThread.dereference_as("_ETHREAD")
                tid = thread.Cid.UniqueThread
                pid = thread.Cid.UniqueProcess

        self.fields['num_pointer'] = str(int(header.PointerCount)) if header else ''
        self.fields['num_handles'] = str(int(header.HandleCount)) if header else ''
        self.fields['mutant_signal_state'] = str(mutant.Header.SignalState) if mutant else ''
        if mutant and (mutant.OwnerThread != 0):
            self.fields['thread'] = str(hex(mutant.OwnerThread)).rstrip('L')
        else:
            self.fields['thread'] =  ''
        self.fields['mutant_name'] = str(header.NameInfo.Name or '') if header else ''
        self.fields['process_id'] = str(pid)
        self.fields['thread_id'] = str(tid)
        