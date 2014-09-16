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
# A plugin for parsing devices from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return DeviceTree(vol)

def getFields():
    return Device().get_field_keys()


class DeviceTree(memobj.MemObjectSet):
    '''
    Parses devices from Windows memory dumps.
    '''   
    
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)
        
        
    def get_alloc(self, addr_space):
        '''
        Mimics volatility's devicetree plugin.
        '''
        import volatility.plugins.malware.devicetree as devicetree

        #for _object_obj, driver_obj, _ in devicetree.DeviceTree(self.vol.config).calculate():
        for driver in devicetree.DeviceTree(self.vol.config).calculate():
            #yield Device(_object_obj, driver_obj, "0x{0:08x}".format(driver_obj.obj_offset))
            yield Device(driver)

            
    def get_child(self):
        return Device()


    '''
    def parse_driver(driver):
    
        offset = "0x{0:08x}".format(driver.obj_offset) if driver else None
        driver_name = str(driver.DriverName or '') if driver else ''
    '''     

 
        
class Device(memobj.MemObject):

    #def __init__(self, _object_obj=None, driver_obj=None, offset=None):
    def __init__(self, driver=None):
        #memobj.MemObject.__init__(self, offset)

        offset = "0x{0:08x}".format(driver.obj_offset) if driver else None
        memobj.MemObject.__init__(self, offset)

        self.fields['driver_name'] = str(driver.DriverName or '') if driver else ''
        self.fields['devices'] = []
        
        import volatility.obj as obj
        import volatility.plugins.malware.devicetree as devicetree

        if driver:    
            for device in driver.devices():
                device_header = obj.Object(
                    "_OBJECT_HEADER",
                    offset=device.obj_offset - device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                    vm=device.obj_vm,
                    native_vm=device.obj_native_vm
                )

                device_name = str(device_header.NameInfo.Name or "")

                new_device = {
                    "device_offset": "0x{0:08x}".format(device.obj_offset),
                    "device_name": device_name,
                    "device_type": devicetree.DEVICE_CODES.get(device.DeviceType.v(), "UNKNOWN"),
                    "devices_attached": []
                }

                self.fields["devices"].append(new_device)

                level = 0

                for att_device in device.attached_devices():
                    device_header = obj.Object(
                        "_OBJECT_HEADER",
                        offset=att_device.obj_offset - att_device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                        vm=att_device.obj_vm,
                        native_vm=att_device.obj_native_vm
                    )

                    device_name = str(device_header.NameInfo.Name or "")
                    name = (device_name + " - " + str(att_device.DriverObject.DriverName or ""))

                    new_device["devices_attached"].append({
                        "level": level,
                        "attached_device_offset": "0x{0:08x}".format(att_device.obj_offset),
                        "attached_device_name": name,
                        "attached_device_type": devicetree.DEVICE_CODES.get(att_device.DeviceType.v(), "UNKNOWN")
                    })

                    level += 1

        self.fields['devices'] = str(self.fields['devices'])            
        self.unique_id = "".join([str(x) for x in self.fields.values()])
            
        self.diff_fields = self.fields.keys()

        
