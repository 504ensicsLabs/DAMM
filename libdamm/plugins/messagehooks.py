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
# A plugin for parsing message hooks from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return MessageHookSet(vol)

def getFields():
    return MessageHook().get_field_keys()


class MessageHookSet(memobj.MemObjectSet):
    '''
    Parses message hooks from Windows memory dumps.
    '''
    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['string'] = ['function', 'module']    
        return defs
    
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's messagehooks plugin.
        '''

        import volatility.plugins.gui.messagehooks as messagehooks

        msghook = messagehooks.MessageHooks(self.vol.config)
        for winsta, atom_tables in msghook.calculate():
            for desk in winsta.desktops():
                for name, hook in desk.hooks():
                    module = msghook.translate_hmod(winsta, atom_tables, hook.ihmod)                   
                    
                    yield MessageHook(desk, winsta, name, hook, module, '<any>', str(hex(int(hook.obj_offset))).rstrip('L'))

                for thrd in desk.threads():
                    info = "{0} ({1} {2})".format(
                        thrd.pEThread.Cid.UniqueThread,
                        thrd.ppi.Process.ImageFileName,
                        thrd.ppi.Process.UniqueProcessId)

                    for name, hook in thrd.hooks():
                        module = msghook.translate_hmod(winsta, atom_tables, hook.ihmod)

                        yield MessageHook(desk, winsta, name, hook, module, info, str(hook.obj_offset).rstrip('L'))

            
    def get_child(self):
        return MessageHook()


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['offset'], 16))
        return elems    

        
class MessageHook(memobj.MemObject):

    def __init__(self, desk=None, winsta=None, name=None, hook=None, module=None, thread=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        self.fields['session'] = str(int(winsta.dwSessionId)) if winsta else None
        self.fields['desktop'] = "{0}\\{1}".format(winsta.Name, desk.Name) if winsta else None
        self.fields['thread'] = str(thread) if thread else None 
        self.fields['filter'] = str(name) if name else None
        self.fields['flags'] = str(hook.flags) if hook else None
        self.fields['function'] = str(hex(int(hook.offPfn))) if hook else None
        self.fields['module'] = str(module) if module else None

