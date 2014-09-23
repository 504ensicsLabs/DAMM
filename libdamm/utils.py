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

DEBUG = False

def debug(msg):
    '''
    Single entry point for printing debug messages to stdout.
    
    @msg: the debug string to print
    '''

    if DEBUG:
        sys.stderr.write("DEBUG: %s\n" % msg)
        sys.stderr.flush()
        


def err(msg):
    sys.stderr.write("ERROR: %s\n" % msg)
        

def set_debug(bool):

    global DEBUG
    DEBUG = bool
