# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.mac.common as common

class mac_lsmod_kext_map(common.AbstractMacCommand):
    """ Lists loaded kernel modules """

    def calculate(self):
        common.set_plugin_members(self)

        p = self.addr_space.profile.get_symbol("_g_kext_map")
        mapaddr = obj.Object("Pointer", offset = p, vm = self.addr_space)
        kextmap = mapaddr.dereference_as("_vm_map") 

        nentries = kextmap.hdr.nentries
        kext     = kextmap.hdr

        for i in range(nentries):
            kext = kext.links.next
           
            if not kext:
                break

            macho = obj.Object("macho_header", offset = kext.start, vm = self.addr_space)

            if macho.is_valid():
                kmod_start = macho.address_for_symbol("_kmod_info")           
            else:
                kmod_start = 0
            
            address  = kext.start
            
            if kmod_start:
                kmod = obj.Object("kmod_info", offset = kmod_start, vm = self.addr_space)
                kmod_off = kmod.obj_offset
                size     = kmod.m('size') 
                ref_cnt  = kmod.reference_count
                ver      = kmod.version
                name     = str(kmod.name)
 
            else:
                kmod_off = 0
                size     = 0
                ref_cnt  = 0
                ver      = 0
                name     = ""
            
            yield kmod_off, address, size, ref_cnt, ver, name

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset (V)", "[addrpad]"),
                                  ("Module Address", "[addrpad]"), 
                                  ("Size", "8"), 
                                  ("Refs", "^8"),
                                  ("Version", "12"),  
                                  ("Name", "")])
        
        for kmod_off, address, size, ref_cnt, ver, name in data:
            self.table_row(outfd,
                           kmod_off, 
                           address, 
                           size, 
                           ref_cnt, 
                           ver, 
                           name)

