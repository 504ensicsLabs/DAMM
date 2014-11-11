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
import volsetup
import plugin
from utils import debug
from utils import set_debug
import sqlite3
import itertools
import db_ops
import warnings


class API:

    def __init__(self, plugins=None, extra_dir=None, memimg='', profile='', kdbg='0', filterp=None, filterp_type=None, output=None, db=None, debug=False, unique_id_fields=None, diff=None):

        set_debug(debug)

        # Use the supplied db file
        self.db = db
        self.db_ops = db_ops.DBOps()
        self.diff = diff

        # Set up plugin system
        self.pluglib = plugin.PluginLibrary()
        self.pluglib.addPluginDir(os.path.join(os.path.dirname(__file__), 'plugins'))
        self.plugins = plugins
        self.plugins = self.pluglib.getPluginList() if (self.plugins and self.plugins[0].lower() == 'all') else self.plugins
        # Add user specified directory of plugins
        if extra_dir:
            self.extra_dir = extra_dir
            self.pluglib.addPluginDir(self.extra_dir)
        
        # Set up user defined output filter
        self.filterp = filterp
        self.filterp_name = filterp.split(":")[0] if filterp else None
        self.filterp_value = filterp.split(":")[1] if filterp else None
        self.filterp_type = filterp_type if filterp_type else 'exact'
        self.unique_id_fields = unique_id_fields        

        # Settings for the volatility subsystem
        self.memimg = memimg
        self.profile = profile
        self.kdbg = kdbg
        self.vol = self.__vol_init()
        # In case we're guessing a profile and need to get the result. Kind of a hack.
        if self.profile == None:
            try:
                self.profile = self.vol.config.get_value('profile')
            except:
                pass


    def set_debug(self, bool):
        '''
        Turn on/off debugging

        @bool: True for debug on
        '''
        set_debug(bool)


    def check_warnings(self, plugins, db):
        '''
        Check for inidcators of malicious activity

        @plugins: list of plugin names
        @db: a DAMM db

        @return: generator of warnings results
        '''
        return warnings.check_warnings(plugins, db)


    def __filter_passed(self, elem, typedefs):
        '''
        Does the given memobj pass the specified filter? 

        @elem: a memobj
        @typedefs: the memobj's typedefs

        @return: True if filter passed
        '''
        filter_passed = False
        # for each field this memobj has of the filter_name type (e.g., pid and ppid)
        for field in typedefs[self.filterp_name]:
            # filter results
            if self.filterp_type.lower() == 'exact':
                debug("exact")
                if self.filterp_value.lower() == elem.fields[field].lower():
                    filter_passed = True
            elif self.filterp_type.lower() == 'partial':
                debug("partial")
                if self.filterp_value.lower() in elem.fields[field].lower():
                    filter_passed = True
            else:
                debug("bad filter type")
                pass 

        return filter_passed


    def filter_plugin(self, plug_results, setobj, changed=False):
        '''
        Apply specified filter to plugin results

        @plug_results: list of plugin output
        @setobj: the setobj for the plugin
        @changed: True if plug_results is from a diff operation

        @return: list of filtered plugin results 
        '''
        # If there is no filter defined, return as is.
        if self.filterp == None:
            return plug_results

        filtered_plug_results = []

        # get type definitions for this memobj type
        typedefs = setobj.get_field_typedefs()
        # if filterp (e.g., 'pid') name is in our typedefs
        if self.filterp_name in typedefs.keys():
            debug("passed keys: %s" % typedefs.keys())
            # for each memoobj
            for elem in plug_results:
                filter_passed = None
                # if changed, these are tuples of the before and after elements
                if changed:
                    filter_passed = (self.__filter_passed(elem[0], typedefs) or self.__filter_passed(elem[1], typedefs))    
                else:    
                    filter_passed = self.__filter_passed(elem, typedefs) 

                debug("filter passed %s" % filter_passed)
                if filter_passed:
                    filtered_plug_results.append(elem)
            
        return filtered_plug_results


    def filter_diff(self, changed, new, setobj):
        '''
        Filter a set of diff results

        @changed: list of pairs of changed plugin results from diff operation
        @new: list of new plugin results from diff operation
        @setobj: the setobj for the plugin

        @return: list of filtered changed objects, list of filtered new 
            objects, the setobj for the plugin
        '''
        # If there is no filter defined, return as is.
        if self.filterp == None:
            return changed, new, setobj

        new = self.filter_plugin(new, setobj)    

        changed = self.filter_plugin(changed, setobj, changed=True)

        return changed, new, setobj


    def run_plugin(self, plug):
        '''                
        Run a single plugin

        @plug: string name of plugin to run

        @return list of plugin results
        '''
        # Are we an empty db? If so, init the db.
        if self.db_ops.db_empty(self.db):
            env = []
            import volatility.plugins.envars as envars
            for task in envars.Envars(self.vol.config).calculate():
                if task.ImageFileName.lower() == 'explorer.exe':
                    for var, val in task.environment_variables():
                        env.append((var, val))
                    break

            self.db_ops.init_db(self.db, self.memimg, self.profile, env)
        
        # If we're a valid loaded plugin
        if plug in self.pluglib.getPluginList():
            # get the setobj for this plugin
            setobj = self.pluglib.getPlugin(plug).handle.getPluginObject(self.vol)
            table_name = self.db_ops.get_table_name(setobj)
            # If we're not currently in the db, run plugin get inserted.
            if not self.db_ops.in_db(self.db, table_name):
                self.db_ops.insert_plugin(setobj, self.db, self.memimg)

            # Operate from the db.
            plug_results = []
            # For each row in the db
            for elem in self.db_ops.get_rows(self.db, table_name):
                # Convert to memobj and add to results
                plug_results.append(setobj.memobj_from_row(elem))
            # Filter the results
            filtered_plug_results = self.filter_plugin(plug_results, setobj)
            # Return the sorted list of results.
            return setobj.sort_elems(filtered_plug_results)
    
        else:
            # Bogus plugin. Return nothing.
            return []


    def run_plugins(self):
        '''
        Run a set of plugins

        @return: generator of memobj results of running plugins
        '''
        for curr in self.plugins:
            for elem in self.run_plugin(curr):
                yield elem


    def run_plugins_grepable(self):
        '''
        Run a set of plugins and return results in grepable format

        @return: generator of grepable string results of running plugins
        '''
        for curr in self.plugins:
            for elem in self.run_plugin(curr):
                yield "%s: %s" % (curr, elem)


    def run_plugins_screen(self):
        '''
        Run a set of plugins and return results in format for terminal display

        @return: generator of screen formatted string results of running 
            plugins
        '''
        for curr in self.plugins:
            # Get appropriate fields lengths for each attribute of the memobjs
            res = []
            plug_results = list(self.run_plugin(curr))
            if plug_results:
                field_lengths = []
                # Start field lengths at attribute name length
                for attr in plug_results[0].fields.keys():
                    field_lengths.append(len(attr))
                # Extend the field lengths if the attribute value is greater
                # length than the name length
                for elem in plug_results:
                    for idx, attr in enumerate(elem.fields.keys()):
                        if elem.fields[attr]:
                            field_lengths[idx] = max(field_lengths[idx], len(elem.fields[attr]))

                # Print a header as first row
                header_done = False
                for elem in plug_results:
                 
                    if not header_done:
                        yield "\n{}".format(curr)  # plugin name
                        yield "\t".join(['{column: <{width}}'.format(column=x, width=field_lengths[i]) for i, x in enumerate(elem.fields.keys())])  # column headers
                        header_done = True
                    
                    yield "\t".join(['{column: <{width}}'.format(column=elem.fields[x], width=field_lengths[i]) for i, x in enumerate(elem.fields.keys())]).strip()

            else:
                yield "\n%s: Nothing to report." % curr


    def run_plugins_tsv(self):
        '''
        Run a set of plugins and return results in tsv format

        @return: generator of tsv formatted string results of running plugins
        '''
        for curr in self.plugins:
            gen = self.run_plugin(curr)

            # Print a header as first row
            header_done = False
            for memobj in gen:
                if not memobj:
                    continue

                if not header_done:
                    yield "\n{}".format(curr)  # plugin name
                    yield "".join([("%s\t" % x) for x in memobj.fields.keys()])  # column headers
                    header_done = True
                yield "".join([("%s\t" % memobj.fields[x]) for x in memobj.fields.keys()])  # memobj
            yield '\n'
            if not header_done:
                yield "\n%s: Nothing to report." % curr

        yield ''


    def __memobj_equals(self, first, second, setobj):
        '''
        Using the fields in diff_fields list, determine if two objects are 
        equal (i.e., their field values are equal)

        @first: a memobj
        @second: another memobj of the same type
        @setobj: the setobj for the memobj type

        @return: True if equal
        '''
        # Use diff_fields if some were specified, else use everything available
        for field in setobj.get_diff_fields():
            debug('Diffing on field: %s' % field)
            foundFirst = field in first.fields
            # Check if presence of field in both First and Second is the same...
            if foundFirst != (field in second.fields):
                return False
            # If field is present in both (implied from previous test and foundFirst), check equality of fields
            elif foundFirst and first.fields[field] != second.fields[field]:
                return False
        return True


    def get_object_dict(self, db, table):
        '''
        Return dict of unique_id : memobj

        @db: a DAMM db
        @table: the table name to make an object dictionary of

        @return: a dict of (unique_id : memobj), the setobj for the memobj type
        '''
        # Table name is of form modulename_setobjname
        # module name == plugin name
        mod_name, setobj_name = table.split("_")
        mod = __import__(mod_name)

        res = {}
        setobj = getattr(mod, setobj_name)()
        for elem in self.db_ops.get_rows(db, table):
            memobj = setobj.memobj_from_row(elem)
            unique_id = ''.join([memobj.fields[x] for x in self.unique_id_fields]) if self.unique_id_fields else setobj.get_unique_id(memobj)
            debug("db: %s table: %s unique_id: %s" % (db, table, unique_id))
            res[unique_id] = memobj

        return res, setobj


    def do_diff(self, table):
        '''
        Perform the differencing operation on two sets of memobjs pulled from
        the two specified dbs.

        @table: the tsble to perform the diff operation on

        @return: list of pairs of changed plugin results from diff operation, 
            list of new plugin results from diff operation, the setobj for the plugin
        '''
        unchanged = []  # unchanged memobjs; don't need this for the moment
        changed = []  # memobjs exist in both dbs, some field values differ
        new = []  # memobjs exist only in db2

        diff_tables = self.db_ops.get_tables(self.diff)
        debug("DB1: %s" % diff_tables)
        db_tables = self.db_ops.get_tables(self.db)
        debug("DB2: %s" % db_tables)
        debug("TABLE: %s" % table)
        
        # get dicts of {unique_id : memobject} 
        diff_dict, setobj = self.get_object_dict(self.diff, table)
        db_dict, _ = self.get_object_dict(self.db, table)

        for elem in db_dict.keys():
            # corresponding memobjs are equal
            if (elem in diff_dict.keys()) and (self.__memobj_equals(diff_dict[elem], db_dict[elem], setobj)):
                unchanged.append(db_dict[elem])
            # corresponding memobjs have differing fields
            elif elem in diff_dict.keys():
                changed.append((diff_dict[elem], db_dict[elem]))
            # db has no corresponding memobj
            else:
                new.append(db_dict[elem])
        
        return self.filter_diff(changed, new, setobj)


    def do_diffs(self):
        '''
        Return the differences between two dbs.

        @return: list of (list of changed memobjs, list of new memobjs, plugin 
            name)
        '''        
        # we can only compare tables that exist in both dbs
        diff_tables = self.db_ops.get_tables(self.diff)
        debug("DB1: %s" % diff_tables)
        db_tables = self.db_ops.get_tables(self.db)
        debug("DB2: %s" % db_tables)
        debug("PLUGIN: %s" % plugin)

        # Can only compare memobjs for tables which exist n both dbs
        compareable = set.intersection(set(diff_tables), set(db_tables))
        compareable = [x for x in compareable if x.split("_")[0] in self.plugins]
        debug("Can't compare %s" % str(set.symmetric_difference(set(diff_tables), set(db_tables))))

        res = []        
        for table in compareable:
            changed, new, setobj = self.do_diff(table)
            res.append((changed, new, table.split("_")[0]))
        return res


    def do_diffs_grepable(self):
        '''
        Return the differences between two dbs in grepable format.

        @return: generator of plugin name, new memobjs, changed memobjs
        '''            
        for changed, new, plugname in self.do_diffs():

            # case nothing to report
            if (changed == []) and (new == []):
                yield "%s: Nothing to report." % plugname
            else:
                if new:
                    for memobj in new:
                        res = "%s: " % plugname 
                        res += "New\t%s" % "\t".join(["%s: %s" % (x, memobj.fields[x]) for x in memobj.fields.keys()])
                        yield res

                if changed:
                    for memobj in changed:
                        old, new = memobj
                        res = ""
                        for field in old.fields.keys():
                            o_field, n_field = old.fields[field], new.fields[field]
                            if o_field == n_field:
                                res += "%s: %s\t" % (field, o_field)
                            else:
                                res += "%s: %s->%s\t" % (field, o_field, n_field)
                        yield "%s: Changed\t%s" % (plugname, res)

            yield ''            


    def do_diffs_screen(self):        
        '''
        Return the differences between two dbs in screen formatted output.

        @return: generator of plugin name, new memobjs, changed memobjs
        '''        
        for changed, new, plugname in self.do_diffs():
            #print "new: %s" % new
            # Case nothing to report
            if (changed == []) and (new == []):
                yield "%s: Nothing to report." % plugname
            else:
                # Plugin name for these results
                yield plugname

                header_done = False

                # Get fields lengths for each attribute of the memobjs
                field_lengths = []
                if changed:
                    for attr in changed[0][0].fields.keys():
                        field_lengths.append(len(attr))
                    for elem in changed:
                        elem = elem[0]
                        for idx, attr in enumerate(elem.fields.keys()):
                            field_lengths[idx] = max(field_lengths[idx], len(elem.fields[attr]))
                else:
                    for attr in new[0].fields.keys():
                        field_lengths.append(len(attr))
                    for elem in new:
                        for idx, attr in enumerate(elem.fields.keys()):
                            field_lengths[idx] = max(field_lengths[idx], len(elem.fields[attr]))

                yield "Status\t%s" % "\t".join(['{column: <{width}}'.format(column=x, width=field_lengths[i]) for i, x in enumerate(elem.fields.keys())])  # column headers

                for elem in new:                    
                    yield "New\t%s" % "\t".join(['{column: <{width}}'.format(column=elem.fields[x], width=field_lengths[i]) for i, x in enumerate(elem.fields.keys())]).strip()

                for elem in changed:
                    old, new = elem
                    res = ""
                    for i, field in enumerate(old.fields.keys()):
                        o_field, n_field = old.fields[field], new.fields[field]
                        if o_field == n_field:
                            res += "%s\t" % '{column: <{width}}'.format(column=o_field, width=field_lengths[i])
                        else:
                            res += "%s\t" % ('{column: <{width}}'.format(column="%s->%s" % (o_field, n_field), width=field_lengths[i]))
                    yield "Changed\t%s" % res

            yield ''


    def do_diffs_tsv(self):
        '''
        Just like do_diffs but generates a tsv formatted report for printing.

        @return: generator of plugin name, new memobjs, changed memobjs
        '''
        for changed, new, plugname in self.do_diffs():

            # case nothing to report
            if (changed == []) and (new == []):
                yield "%s: Nothing to report." % plugname
            else:
                # plugin name for these results
                yield plugname

                header_done = False

                # for each new memobj, yield output lines
                if new:
                    for memobj in new:
                        if not header_done:
                            yield "Status\t%s" % "".join([("%s\t" % x) for x in memobj.fields.keys()])  # column headers
                            header_done = True

                        yield "New\t%s" % "".join([("%s\t" % memobj.fields[x]) for x in memobj.fields.keys()])  # memobj

                # for each changed memobj, yield output lines        
                if changed:
                    for memobj in changed:

                        if not header_done:
                            yield "Status\t%s" % "".join([("%s\t" % x) for x in memobj[0].fields.keys()])  # column headers
                            header_done = True

                        old, new = memobj
                        res = ""
                        for field in old.fields.keys():
                            o_field, n_field = old.fields[field], new.fields[field]
                            if o_field == n_field:
                                res += "%s\t" % o_field
                            else:
                                res += "%s->%s\t" % (o_field, n_field)
                        yield "Changed\t%s" % res

            yield ''


    # Getter Setter Goodness (Madness?)

    def query_db(self):
        '''
        @return: the list of envars stored in the db, the list of tables stored 
            in the db
        '''
        tables = self.db_ops.get_tables(self.db)
        envars = self.db_ops.get_meta(self.db)
        return envars, tables


    def get_pluglib(self):
        '''
        @return: the library of loaded plugins
        '''        
        return self.pluglib


    def loaded_plugins(self):
        '''
        @return: list of loaded plugins
        '''
        return plugin.loaded_plugins(self.pluglib)


    def loaded_plugins_info(self):
        '''
        @return: string info on loaded plugin memobjs with fields
        '''
        return plugin.loaded_plugins_info(self.pluglib)


    def vol_profiles_info(self):
        '''
        @return: string info available Volatility profiles
        '''
        return self.vol.vol_profiles_list()


    def get_vol_profiles(self):
        return self.vol.vol_profiles()


    def get_vol(self):
        '''
        @return: the underlying Volsetup instance
        '''
        return self.vol


    def set_plugins(self, plugins):
        '''
        Set the list of plugins to run.

        @plugins: list of strings of plugin names to run
        '''
        self.plugins = plugins
        self.plugins = self.pluglib.getPluginList() if (self.plugins[0].lower() == 'all') else self.plugins


    def get_plugins(self):
        '''
        @return list of strings of plugin names to run
        '''
        return self.plugins


    def set_extra_dir(self, extra_dir):
        '''
        Set a user-defined directory to search for plugins.

        @extra_dir: string direcotry path
        '''
        self.extra_dir = extra_dir
        self.pluglib.addPluginDir(self.extra_dir)


    def get_extra_directory(self):
        '''
        @ return: string name of extra directory of plugins
        '''
        return self.extra_dir


    def set_memimg(self, fname):
        '''
        Set the memory image to run plugins on.

        @fname: name if memory image file 
        '''
        self.vol.set_memimg(fname)


    def get_memimg(self):
        '''
        @return name if memory image file 
        '''
        return self.vol.config.location


    def set_profile(self, profile):
        '''
        Set the Voltility profile to use, e.g., WinXPSP2x86.

        @profile: string Volatility profile
        '''
        self.vol.set_profile(profile)


    def get_profile(self):
        '''
        @return: string for Volatility profile 
        '''
        return self.vol.config.profile


    def set_kdbg(self, kdbg):
        '''
        Set the Voltility kdbg to use

        @profile: hex string Volatility kdbg
        '''
        self.vol.set_kdbg(kdbg)


    def get_kdbg(self):
        '''
        @return: hex string for Volatility kdbg 
        '''
        return self.vol.config.kdbg


    def set_filterp(self, filterp):
        '''
        Set the filter to apply to results.

        @filterp: string representation of colon separated filter name and 
            value, e.g., pid:42
        '''
        self.filterp = filterp


    def get_filterp(self):
        '''
        @return: string representation of filter name and value
        '''
        return self.filterp


    def set_filterp_type(self, filterp_type):
        '''
        Set the filter type to apply to results.

        @filterp_type: either string 'exact' or 'partial' for type of filtering
        '''
        self.filterp_type = filterp_type


    def get_filterp_type(self):
        '''
        @return: string filterp type, either 'exact' or 'partial'
        '''
        return self.filterp_type


    def set_db(self, db):
        '''
        Set the name of the db to use for persistence. If 'db' is not a db, it
        will be created and used for persistence for newly generated results.

        @db: string name of database to use 
        '''
        self.db = db


    def get_db(self):
        '''
        @return: string name of database to use 
        '''
        return self.db


   # private internal functions


    def __vol_init(self):
        '''
        Initialize the underlying Volatility runtime.
        '''
        return volsetup.VolSetup(self.profile, self.kdbg, self.memimg)

