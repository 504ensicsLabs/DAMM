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

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.imageinfo as imageinfo
import os.path
from utils import debug
import sys


class VolSetup:
    '''
    This class manages data that the underlying volatility system requires.
    '''

    def __init__(self, profile, kdbg, memimg):

        # volatility black magic
        registry.PluginImporter()
        self.config = conf.ConfObject()
        self.config.optparser.set_conflict_handler(handler="resolve")
        registry.register_global_options(self.config, commands.Command)

        if memimg:
          
            self.base_conf = {'profile': profile,
                'use_old_as': None,
                'kdbg': None if kdbg is None else int(kdbg, 16),
                'help': False,
                'kpcr': None,
                'tz': None,
                'pid': None,
                'output_file': None,
                'physical_offset': None,
                'conf_file': None,
                'dtb': None,
                'output': None,
                'info': None,
                'location': "file://" + memimg,
                'plugins': None,
                'debug': None,
                'cache_dtb': True,
                'filename': None,
                'cache_directory': None,
                'verbose': None,
                'write': False}

            # set the default config
            for k, v in self.base_conf.items():
                self.config.update(k, v)
         
            if profile == None:
                profile = self.guess_profile(memimg)
                sys.stderr.write("Using profile: %s\n" % profile)     

            
    def guess_profile(self, memimg):
        '''
        Using one of the user-specified memory image files, tries to guess a
        working volatility profile. This can easily take on the order of
        minutes.
        '''
        sys.stderr.write("Auto configuring profile. This may take a some time.\n")

        self.set_memimg(memimg)
        
        # Must use a dummy profile or volatility dies
        self.set_profile('WinXPSP2x86')

        chosen = None
        profilelist = [p.__name__ for p in registry.get_plugin_classes(obj.Profile).values()]
        for profile in profilelist:
            self.config.update('profile', profile)
            addr_space = utils.load_as(self.config, astype='any')
            if hasattr(addr_space, "dtb"):
                chosen = profile
                break
        
        return chosen
        

    def vol_profiles(self):

        # Load available volatility profiles
        prof = obj.Profile
        registry.PluginImporter()
        profList = sorted([i.__name__.split('.')[-1] for i in prof.__subclasses__()])
        return profList

        
    def vol_profiles_list(self):
        '''
        Returns info available volatility profiles.
        '''
        profList = self.vol_profiles()

        res = '\nPROFILES:\n%s\n' % ('-' * 15)
        for cur in profList:
            res += '\t%s\n' % cur

        return res
    
    
    def set_memimg(self, fname):
    
        if os.path.isfile(fname):
            self.config.update('location', "file:///%s" % os.path.abspath(fname))
        else:
            debug("File: %s does not exist." % fname)
        
        
    def set_profile(self, profile):
        
        if profile in self.vol_profiles_list():
            self.config.update('profile', profile)
        else:
            debug("profile: %s does not exist." % profile)
    
    
    def set_kdbg(self, kdbg):
        self.config.update('kdbg', None if kdbg is None else int(kdbg, 16))
        
 
                