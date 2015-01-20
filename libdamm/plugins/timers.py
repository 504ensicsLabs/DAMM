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
# A plugin for parsing timers from Windows memory dumps.
#


import libdamm.memory_object as memobj


def getPluginObject(vol):
    return TimerSet(vol)

def getFields():
    return Timer().get_field_keys()


class TimerSet(memobj.MemObjectSet):
    '''
    Parses timers from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        # BUG!!! the time has some f'ed up formatting
        defs['time'] = ['due_time']
        defs['string'] = ['module']    
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's timers plugin.
        '''
        import volatility.plugins.malware.timers as timers
        
        for timer, module in timers.Timers(self.vol.config).calculate():
            t = Timer(timer, module, str(hex(timer.obj_offset)).rstrip('L'))
            #print t
            yield t    
            
            
    def get_child(self):
        return Timer()


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['offset'], 16))
        return elems
        
        
class Timer(memobj.MemObject):

    def __init__(self, timer=None, module=None, offset=None):
        memobj.MemObject.__init__(self, offset)
            
        due_time = "{0:#010x}:{1:#010x}".format(timer.DueTime.HighPart, timer.DueTime.LowPart)  if timer else ''

        self.fields['due_time'] = str(due_time)
        self.fields['period'] = str(int(timer.Period)) if timer else '' 
        self.fields['signaled'] = ('Yes' if timer.Header.SignalState.v() else '-') if timer else ''
        self.fields['routine'] = str(hex(int(timer.Dpc.DeferredRoutine))) if timer else ''
        self.fields['module'] = str(module.BaseDllName or '') if module else 'UNKNOWN'
