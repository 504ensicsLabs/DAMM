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
# A plugin for dealing with EVT log entries Windows memory dumps.
#

import libdamm.memory_object as memobj
import sys


def getPluginObject(vol):
    return EvtlogSet(vol)


def getFields():
    return Evtlog().get_field_keys()


class EvtlogSet(memobj.MemObjectSet):
    '''
    Manages sets of Windows eventlog entries parsed from memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['time'] = ['time_written']
        defs['string'] = ['path', 'computer_name', 'sid_string', 'source', 'event_type', 'msg']
        return defs
    

    @staticmethod
    def is_valid_profile(profile):
        """This plugin is valid on XP and 2003"""
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

		
    def get_scan(self):
        '''
        Mimics volatiltiy's evtlogs plugin - scans the memory image carving out objects
        which look like Windows processes.
        '''
        import volatility.plugins.evtlogs as evtlogs
        import volatility.utils as utils

        addr_space = utils.load_as(self.vol.config)
        
        if self.is_valid_profile(addr_space.profile):
            e = evtlogs.EvtLogs(self.vol.config)
            for name, data in e.calculate():
                for info in e.parse_evt_info(name, data):
                    yield Evtlog(info, 0)
        else:
            import sys 
            sys.stdout.write("evtlogs plugin does not support %s.\n" % self.vol.config.get_value('profile'))            


    def get_child(self):
        return Evtlog()                 

                       
class Evtlog(memobj.MemObject):

    def __init__(self, info=None, offset=None): 

        # Must init superclass
        memobj.MemObject.__init__(self, offset)
        
        del(self.fields['offset'])

        info = list(info) if info else None
        # These are all of the process fields we know about
        self.fields['time_written'] = info[0] if info else None
        self.fields['path'] = info[1] if info else None
        self.fields['computer_name'] = info[2] if info else None
        self.fields['sid_string'] = info[3] if info else None
        self.fields['source'] = info[4] if info else None
        self.fields['event_id'] = info[5] if info else None
        self.fields['event_type'] = info[6] if info else None
        self.fields['msg'] = info[7] if info else None
        