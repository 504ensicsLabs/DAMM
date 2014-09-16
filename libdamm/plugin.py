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

import os
import sys
import glob
from utils import debug


def loaded_plugins_info(plugLibrary):
    '''
    Returns info on loaded plugins with field options
    
    @plugLibrary: library of loaded plugins
    '''
    plugList = sorted(plugLibrary.getPluginList())
    res = '\nPLUGINS & ATTRIBUTES:\n%s\n' % ('-' * 15)
    res += '\tall\n'
    for cur in plugList:
        res += '\t%s   %s\n' % (cur, '-' * 10)
        for field in plugLibrary.getPlugin(cur).handle.getFields():
            res += '\t\t%s\n' % field

    return res


def loaded_plugins(plugLibrary):
    return sorted(plugLibrary.getPluginList())


class PluginInformation():

    def __init__(self, name, handle):
        self.name = name
        self.handle = handle


class PluginLibrary():

    def __init__(self):
        self._library = {}

    def remPlugin(self, name):
        del self._library[name]
        # TODO signal model update

    def getPlugin(self, name):
        return self._library[name]

    def getPluginList(self):
        return self._library.keys()

    def getPlugins(self):
        return self._library.items()


    def addPlugin(self, path):

        # debug('Adding plugin: %s' % path)
        if not os.path.exists(path):
            return (False, '%s doesn\'t exist' % (path))

        if not os.path.isfile(path) or not path[-3:].lower() == '.py':
            return (False, '%s isn\'t python file' % (path))

        # TODO: either change to imp.import_source(...) for path based loading
        #    or change over just to name based loading
        modName = os.path.basename(path)[:-3]
        mod = __import__(modName)
        modInfo = PluginInformation(modName, mod)
        # self._library[modName] = mod
        self._library[modName] = modInfo

        # TODO signal model update
        return (True, '%s loaded' % (path))


    def addPluginDir(self, path):
        if not os.path.isdir(path):
            return (False, 'Directory %s doesn\'t exist' % (path))
        seen = 0
        added = 0
        # TODO check if dir already in path
        sys.path.append(path)
        for pyFile in glob.iglob(os.path.join(path, '*.py')):
            seen += 1
            status, msg = self.addPlugin(pyFile)
            # debug(msg)
            if status:
                added += 1
        return (True, '%s : %i of %i plugins successfully loaded' % (path, added, seen))

