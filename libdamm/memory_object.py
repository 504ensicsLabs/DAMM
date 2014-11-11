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

import sys
import os
import volatility.utils
import utils
from utils import debug
from collections import OrderedDict


class MemObjectSet(object):
    '''
    The parent class for all sets of objects parsed from a memory dump.
    '''
    @staticmethod
    def get_field_typedefs():
        '''
        Each memobj type can define types for attributes. These types are used 
        for filtering. 
        '''
        defs = {}
        return defs


    def __init__(self, vol):
        '''
        @vol: a Volsetup object
        '''
        self.vol = vol
        self.memobjs = []


    def get_child(self):
        '''
        Each setobj has a corresponding memobj

        @return: a memobj instance for the setobj
        '''
        return None


    def memobj_from_row(self, row):
        '''
        Convert db row back to memobj

        @row: a DAMM db row

        @return: a memobj created from the row
        '''
        memobj = self.get_child()
        fields = memobj.fields.keys()
        for i, name in enumerate(row):
            memobj.fields[fields[i]] = row[i]

        return memobj


    def analyze_file(self):
        '''
        Parse all the memobjs from memimg

        @return: generator of memobjs 
        '''
        for elem in self.get_all():
            debug("analyze_file: %s" % elem)
            self.memobjs.append(elem)
            yield elem


    def get_offset(self, vol_obj, convert_to_phys=False):
        '''
        Return the offset of an object form a memory dump

        @vol_object: an object from a memory dump
        @convert_to_physical: if True convert virual address to physical

        @return: a hex formatted address
        '''
        offset = vol_obj.obj_offset
        if convert_to_phys:
            offset = vol_obj.obj_vm.vtop(vol_obj.obj_offset)
        return hex(offset).rstrip("L")  # strip the "long" marker, if it exists


    def get_all(self):
        '''
        Accumulate all instances of an object type in a memory image. Some
        memobjs will have allocated and unallocated instances in a memory
        capture, collected by get_alloc() and get_scan() functions respectively

        Use of this function requires that calling instance defines two
        functions:
            get_scan(): returning a set of carved objects
            get_alloc(): returning a set of allocated instances

        @addr_space: the currently valid volatility address_space

        @return: generator of memobjs
        '''
        elems = {}
        addr_space = volatility.utils.load_as(self.vol.config)
        for elem in self.get_scan():
            elems[self.get_unique_id(elem)] = elem
        for elem in self.get_alloc(addr_space):
            elems[self.get_unique_id(elem)] = elem

        value = None
        for _, v in elems.items():
            yield v


    def get_alloc(self, addr_space):
        '''
        @return: allocated memobjs from a memory dump.
        '''
        return []


    def get_scan(self):
        '''
        @return: unallocated memobjs from a memory dump.
        '''
        return []


    def get_diff_fields(self):
        '''
        @return: the default set of memobj fields to use in a diff operation.
        '''
        return self.get_child().fields.keys()


    def get_unique_id(self, elem):
        '''
        @return: the default set of memobj fields to use to determine the
        the object's uniqueness.        
        '''
        return (elem.fields[x] for x in elem.fields.keys())


    def sort_elems(self, elems):
        '''
        @elems: a list of memobjects

        @return: sorted list of memobjs
        '''
        elems.sort(key=lambda x: x.fields[x.fields.keys()[0]].lower())
        return elems


class MemObject(object):
    '''
    The superclass for all objects parsed from memory captures.
    '''
    def __init__(self, offset):
        '''
        All memobj attributes are stored in the fields dictionary

        @offset: the offset in the memory image of this object
        '''
        # Using ordereddict gets us free logical ordering when printing results
        self.fields = OrderedDict()

        self.fields['offset'] = offset
    

    def get_field_keys(self):
        '''
        Since using ordereddict, prettier ordering based on the programmatic 
        order that fields are entered

        @return: an ordered list of fields keys for the memobj
        '''
        return self.fields.keys()


    def __str__(self):
        '''
        @return: string of all fields of a memobj
        '''
        return "".join(["%s: %s\t" % (elem, self.fields[elem]) for elem in self.fields.keys()])


