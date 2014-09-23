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
# A plugin for parsing installed services from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return ServiceSet(vol)

def getFields():
    return Service().get_field_keys()


class ServiceSet(memobj.MemObjectSet):
    '''
    Manages sets of installed services parsed from memory dumps.
    '''    
    @staticmethod
    def get_field_typedefs():      
        defs = {}
        defs['pid'] = ['process_id']
        defs['string'] = ['service_name', 'display_name', 'binary_path', 'service_DLL']    
        return defs
        
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
    def get_scan(self):
        '''
        Mimics volatiltiy's svcscan - scans the memory image carving out objects
        which look like Windows processes.
        '''
        import volatility.plugins.malware.svcscan as svcscan
        import volatility.plugins.registry.registryapi as registryapi
        
        regapi = registryapi.RegistryApi(self.vol.config)
        ccs = regapi.reg_get_currentcontrolset()
        
        for rec in svcscan.SvcScan(self.vol.config).calculate():
            svcdll = regapi.reg_get_value(
                          hive_name = "system", 
                          key = "{0}\\services\\{1}\\Parameters".format(ccs, rec.ServiceName.dereference()), 
                          value = "ServiceDll")
   
            yield Service(rec, svcdll, str(hex(rec.obj_offset)))

            
    def get_child(self):
        return Service()            
            

    def get_unique_id(self, svc):
        return (svc.fields['process_id'], svc.fields['service_name'], svc.fields['display_name'], svc.fields['service_type'], svc.fields['binary_path'], svc.fields['service_DLL'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: x.fields['display_name'].lower())
        return elems
        

class Service(memobj.MemObject):


    def __init__(self, rec=None, svcdll=None, offset=None):

        memobj.MemObject.__init__(self, offset)

        # These are all of the service fields we know about
        self.fields['service_order'] =  str(rec.Order) if rec else None
        self.fields['service_start'] = str(rec.Start) if rec else None
        self.fields['process_id'] =  str(rec.Pid) if rec else None
        self.fields['service_name'] = str(rec.ServiceName.dereference()) if rec else None
        self.fields['display_name'] = str(rec.DisplayName.dereference()) if rec else None
        self.fields['service_type'] = str(rec.Type) if rec else None
        self.fields['service_state'] = str(rec.State) if rec else None
        self.fields['binary_path'] = str(rec.Binary) if rec else None
        self.fields['service_DLL'] = str(svcdll) if rec else None
