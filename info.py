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


'''
    The following is located here instead of __init__ because
    pyinstaller will not happily import the project's __init__
'''
name = 'DAMM'
_major = '1'
_minor = '0'
_revision = filter(str.isdigit, '$Revision: 16 $')
_qualifier = 'alpha'
__version__ = '{major}.{minor}.{revision}{qualifier}'.format(major=_major, minor=_minor, revision=_revision, qualifier=_qualifier)
