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
# A plugin for parsing MFT entries from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return MFTSet(vol)

def getFields():
    return MFTEntry().get_field_keys()


class MFTSet(memobj.MemObjectSet):
    '''
    Parses MFT entries from Windows memory dumps.
    '''
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        
    def valid_body(self, body):

        import sys
        try:
            offset = body.split("|")[1].split("Offset: ")[1].strip(")")
        except:
            sys.stderr.write("Error: %s\n" % body)
            return False
        return True        



    def get_alloc(self, addr_space):
        '''
        Mimics volatility's mftparser plugin.
        '''
        import volatility.plugins.mftparser as mftparser

        parser = mftparser.MFTParser(self.vol.config)

        # Some notes: every base MFT entry should have one $SI and at lease one $FN
        # Usually $SI occurs before $FN
        # We'll make an effort to get the filename from $FN for $SI
        # If there is only one $SI with no $FN we dump whatever information it has
        
        for offset, mft_entry, attributes in parser.calculate():
            si = None
            full = ""
            datanum = 0
            for a, i in attributes:
                # we'll have a default file size of -1 for records missing $FN attributes
                # note that file size found in $FN may not actually be accurate and will most likely
                # be 0.  See Carrier, pg 363
                size = -1
                if a.startswith("STANDARD_INFORMATION"):
                    if full != "":
                        # if we are here, we've hit one $FN attribute for this entry already and have the full name
                        # so we can dump this $SI
                        body = "0|{0}\n".format(i.body(full, mft_entry.RecordNumber, size, offset))
                        if self.valid_body(body):
                            yield MFTEntry(body)

                    elif si != None:
                        # if we are here then we have more than one $SI attribute for this entry
                        # since we don't want to lose its info, we'll just dump it for now
                        # we won't have full path, but we'll have a filename most likely
                        body = "0|{0}\n".format(i.body("", mft_entry.RecordNumber, size, offset))
                        if self.valid_body(body):
                            yield MFTEntry(body)

                    elif si == None:
                        # this is the usual case and we'll save the $SI to process after we get the full path from the $FN
                        si = i
                elif a.startswith("FILE_NAME"):
                    if hasattr(i, "ParentDirectory"):
                        full = mft_entry.get_full_path(i)
                        size = int(i.RealFileSize)
                        body = "0|{0}\n".format(i.body(full, mft_entry.RecordNumber, size, offset))
                        if self.valid_body(body):
                            yield MFTEntry(body)


                        if si != None:
                            body = "0|{0}\n".format(si.body(full, mft_entry.RecordNumber, size, offset))
                            if self.valid_body(body):
                                yield MFTEntry(body)

                            si = None
                elif a.startswith("DATA"):
                    pass
 

            if si != None:
                # here we have a lone $SI in an MFT entry with no valid $FN.  This is most likely a non-base entry
                body = "0|{0}\n".format(si.body("", mft_entry.RecordNumber, -1, offset))
                if self.valid_body(body):
                    yield MFTEntry(body)

            
                  
    def get_child(self):
        return MFTEntry()        


    def get_unique_id(self, bentry):
        return bentry.fields['name']    


    def sort_elems(self, elems):
        elems.sort(key=lambda x: x.fields['name'].lower())
        return elems
        


class MFTEntry(memobj.MemObject):

    def __init__(self, body_string=None):

        if body_string:
            offset = body_string.split("|")[1].split("Offset: ")[1].strip(")")     
        else:
            offset = None

        memobj.MemObject.__init__(self, offset)

        import time
        
        self.fields['md5'] = body_string.split("|")[0] if body_string else ''
        self.fields['name'] = body_string.split("|")[1].split("(Offset: ")[0].strip() if body_string else ''
        self.fields['inode'] = body_string.split("|")[2] if body_string else ''
        self.fields['mode_as_string'] = body_string.split("|")[3] if body_string else ''
        self.fields['UID'] = body_string.split("|")[4] if body_string else ''
        self.fields['GID'] = body_string.split("|")[5] if body_string else ''
        self.fields['size'] = body_string.split("|")[6] if body_string else ''
        try:
            self.fields['atime'] = time.ctime(int(body_string.split("|")[7])) if body_string else ''
        except:
            self.fields['atime'] = 'BAD'
        try:    
            self.fields['mtime'] = time.ctime(int(body_string.split("|")[8])) if body_string else ''
        except:
            self.fields['mtime'] = 'BAD'
        try:
            self.fields['ctime'] = time.ctime(int(body_string.split("|")[9])) if body_string else ''
        except:
            self.fields['ctime'] = 'BAD'
        try:
            self.fields['crtime'] = time.ctime(int(body_string.split("|")[10].strip())) if body_string else ''
        except:
            self.fields['crtime'] = 'BAD'

