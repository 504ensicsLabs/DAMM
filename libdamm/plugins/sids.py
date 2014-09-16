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
# A plugin for parsing SIDS from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return SIDSet(vol)

def getFields():
    return SID().get_field_keys()


class SIDSet(memobj.MemObjectSet):
    '''
    Parses SIDS from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_id']
        defs['string'] = ['filename', 'sid_string', 'sid_name']    
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's getsids plugin.
        '''
        import volatility.plugins.getsids as getsids

        for task in getsids.GetSIDs(self.vol.config).calculate():
            token = task.get_token()

            if not token:
                continue

            for sid_string in token.get_sids():
                yield SID(task, sid_string, 0)

            
    def get_child(self):
        return SID()

    
    def sort_elems(self, elems):
        elems.sort(key=lambda x: (int(x.fields['process_id']), x.fields['sid_name']))
        return elems
        

class SID(memobj.MemObject):

    def __init__(self, task=None, sid_string=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        import volatility.plugins.getsids as getsids

        if sid_string:
            if sid_string in getsids.well_known_sids:
                sid_name = " {0}".format(getsids.well_known_sids[sid_string])
            else:
                sid_name_re = getsids.find_sid_re(sid_string, getsids.well_known_sid_re)
                if sid_name_re:
                    sid_name = " {0}".format(sid_name_re)
                else:
                    sid_name = ""
        else:
            sid_name = ''
            sid_string = ''            
            

        del(self.fields['offset'])    
        self.fields['filename'] = str(task.ImageFileName) if task else None
        self.fields['process_id'] = str(int(task.UniqueProcessId)) if task else None
        self.fields['sid_string'] = str(sid_string)
        self.fields['sid_name'] = str(sid_name)
