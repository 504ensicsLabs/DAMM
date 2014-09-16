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

import sqlite3
from utils import debug
import plugin


def temp(s):
    return ('tmp' in s.lower() or 'temp' in s.lower())


def process_warnings(procs, envars):

    # BUG: We make the assumption that the system drive is C: until I find a better method
    profile = [x[1] for x in envars if x[0].lower() == 'profile'][0]
    sysroot = [x[1] for x in envars if x[0].lower() == 'systemroot'][0]

    known_processes_XP = {
        'system'        : { 'pid' : 4, 'image_path' : '', 'user_account' : 'Local System', 'parent' : ['None'], 'singleton' : True, 'prio' : '8' },
        'smss.exe'      : {'image_path' : '%s\System32\smss.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : ['system'], 'singleton' : True, 'session' : '', 'prio' : '11' },
        'lsass.exe'     : {'image_path' : '%s\system32\lsass.exe' % sysroot, 'user_account' : 'Local System', 'parent' : ['winlogon.exe'], 'singleton' : True, 'session' : '0', 'prio' : '9' },
        'winlogon.exe'  : {'image_path' : '%s\system32\winlogon.exe' % sysroot, 'user_account' : 'Local System', 'session' : '0', 'prio' : '13' },
        'csrss.exe'     : {'image_path' : '%s\system32\csrss.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'session' : '0', 'prio' : '13' },
        'services.exe'  : {'image_path' : '%s\system32\services.exe' % sysroot, 'parent' : ['winlogon.exe'], 'session' : '0', 'prio' : '9' },
        'svchost.exe'   : {'image_path' : '%s\System32\svchost.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'], 'parent' : ['services.exe'], 'singleton' : False, 'session' : '0', 'prio' : '8' },
        'explorer.exe'  : {'image_path' : '%s\explorer.exe' % sysroot, 'prio' : '8' },
    }

    known_processes_Vista = {
        'system'        : { 'pid' : 4, 'image_path' : '', 'user_account' : 'Local System', 'parent' : ['None'], 'singleton' : True, 'prio' : '8' },
        'smss.exe'      : {'image_path' : '%s\System32\smss.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : ['System'], 'singleton' : True, 'session' : '', 'prio' : '11' },
        'wininit.exe'   : {'image_path' : '%s\System32\wininit.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : ['smss.exe'], 'session' : '0', 'children' : False, 'prio' : '13' },
        'lsass.exe'     : {'image_path' : '%s\system32\lsass.exe' % sysroot, 'user_account' : 'Local System', 'parent' : ['wininit.exe'], 'singleton' : True, 'session' : '0', 'prio' : '9' },
        'winlogon.exe'  : {'image_path' : '%s\system32\winlogon.exe' % sysroot, 'user_account' : 'Local System', 'session' : '1' , 'prio' : '13'},
        'csrss.exe'     : {'image_path' : '%s\system32\csrss.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'prio' : '13' },
        'services.exe'  : {'image_path' : '%s\system32\services.exe' % sysroot, 'parent' : ['wininit.exe'], 'session' : '0', 'prio' : '9' },
        'svchost.exe'   : {'image_path' : '%s\System32\svchost.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'], 'parent' : ['services.exe'], 'singleton' : False, 'session' : '0', 'prio' : '8' },
        'lsm.exe '      : {'image_path' : '%s\System32\lsm.exe' % sysroot, 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : ['wininit.exe'], 'session' : '0', 'prio' : '8' },
        'explorer.exe'  : {'image_path' : '%s\explorer.exe' % sysroot, 'prio' : '8' },
    }

    # Differentiate between OSs
    if profile.startswith('WinXP'):
        known_processes = known_processes_XP
    elif profile.startswith('Win7') or profile.startswith('Vista'):
        known_processes = known_processes_Vista
    else:
        known_processes = { }

    # Make some useful dicts
    procs_by_name = {}
    procs_by_pid = {}
    for elem in procs:
        procs_by_name[elem.fields['name']] = elem
        procs_by_pid[elem.fields['pid']] = elem
    

    # Checks for all processes; if the fields are populated, why not?                    
    for elem in procs:

        # Look for temp file or directories
        if temp(elem.fields['image_path_name']):
            yield "%s (pid: %s) image path in temp." % (elem.fields['name'], elem.fields['pid'])            
        if temp(elem.fields['command_line']):
            yield "%s (pid: %s) command line contains temp." % (elem.fields['name'], elem.fields['pid'])

        # Fake exit time, still has threads running    
        if (elem.fields['exit_time'] != '') and (elem.fields['threads'] != '0'):
            yield "%s (pid: %s) has an exit time of %s and but also has %s running threads." % (elem.fields['name'], elem.fields['pid'], elem.fields['exit_time'], elem.fields['threads'])

        # Process unlinked from list            
        if elem.fields['pslist'] == 'False':
            others = 0 
            for xview in ['psscan', 'thrdproc', 'pspcid', 'csrss', 'session', 'deskthrd']:
                if elem.fields[xview] == 'True':
                    others += 1
            # Is this a reasonable heauristic?
            if others > 3:
                yield "%s (pid: %s) may be a hidden process." % (elem.fields['name'], elem.fields['pid'])
            
 

    # Checks all for known processes, using constraints dict above        
    for elem in [x for x in procs if x.fields['name'].lower() in known_processes.keys()]:

        # For allocated, running processes only.       
        if elem.fields['pslist'] == 'True' and elem.fields['exit_time'] == '':

            # Get the set of constraints for this known process
            constraints = known_processes[elem.fields['name'].lower()]

            if constraints.get('pid'):
                expected = int(constraints['pid'])
                actual = int(elem.fields['pid'])
                if actual != expected:
                    yield "%s pid expected: %s, actual: %s." % (elem.fields['name'], expected, actual)

            if constraints.get('parent'):
                expected = constraints['parent']
                ppid = elem.fields['ppid']
                if ppid == '0':
                    actual = 'None'
                else:
                    actual = procs_by_pid.get(elem.fields['ppid']).fields['name']
                if actual and actual.lower() not in [p.lower() for p in expected]:
                    yield "%s (pid: %s) parent process expected: %s, actual: %s." % (elem.fields['name'], elem.fields['pid'], expected, actual)

            if constraints.get('singleton'):
                instances = 0
                for e in procs:
                    if e.fields['name'] == elem.fields['name'] and e.fields['pslist'] == 'True' and e.fields['exit_time'] == '': 
                        instances += 1
                if instances != 1:
                    yield "%s (pid: %s) has %s instances. Only one instance should exist!" % (elem.fields['name'], elem.fields['pid'], instances)

            if constraints.get('image_path'):
                expected = constraints['image_path']
                actual = str(elem.fields['image_path_name'])
                if actual.startswith('\\??\\'):
                    actual = actual.lstrip('\\??\\')
               
                # Not really sure if this is the right move ... time will tell
                if actual.startswith('\\SystemRoot'):
                    actual = actual.replace('\\SystemRoot', sysroot)
                  
                if actual.lower() != expected.lower():
                    yield "%s (pid: %s) image path expected: %s, actual: %s." % (elem.fields['name'], elem.fields['pid'], expected, elem.fields['image_path_name'])

            if constraints.get('session'):        
                expected = constraints['session']
                actual = elem.fields['session_id']
                if actual != expected:
                    yield "%s (pid: %s) session_id expected: %s, actual: %s." % (elem.fields['name'], elem.fields['pid'], expected, actual)

            if constraints.get('prio'):        
                expected = int(constraints['prio'])
                actual = int(elem.fields['prio'])
                if actual != expected:
                    yield "%s (pid: %s) base priority expected: %s, actual: %s." % (elem.fields['name'], elem.fields['pid'], expected, actual)


def injection_warnings(injects, envars):

    # Look for MZ in 'content'
    for inject in injects:
        if 'MZ' in inject.fields['content']:
            yield "%s (pid: %s) has PE header in injection." % (inject.fields['task_image_file_name'], inject.fields['task_unique_proces_id'])


def dll_warnings(dlls, envars):

    
    for dll in dlls:

        # Is dll run from temp directory?
        if temp(dll.fields['dll_mapped_path']):
            yield "%s (pid: %s) has temp in dll_mapped_path." % (dll.fields['dll_mapped_path'], dll.fields['process_id'])
        if temp(dll.fields['load_full_dll_name']):
            yield "%s (pid: %s) has temp in load_full_dll_name." % (dll.fields['load_full_dll_name'], dll.fields['process_id'])
        if temp(dll.fields['init_full_dll_name']):
            yield "%s (pid: %s) has temp in init_full_dll_name." % (dll.fields['init_full_dll_name'], dll.fields['process_id'])
        if temp(dll.fields['mem_full_dll_name']):
            yield "%s (pid: %s) has temp in mem_full_dll_name." % (dll.fields['mem_full_dll_name'], dll.fields['process_id'])

        # No name or extension or bad extension
        pieces = dll.fields['dll_mapped_path'].rsplit('.', 1)
        if len(pieces) < 2:
            yield "%s (pid: %s) has no extension." % (dll.fields['dll_mapped_path'], dll.fields['process_id'])
        elif dll.fields['dll_mapped_path'].rsplit('.', 1)[1].lower() in ['d1l', 'dl1', 'd11']:
            yield "%s (pid: %s) has a 1 (one) in the extension." % (dll.fields['dll_mapped_path'], dll.fields['process_id'])

        # Hidden dlls
        if dll.fields['dll_mapped_path'].lower().endswith('.dll'):
            if not (dll.fields['dll_in_load'] == 'True') and (dll.fields['dll_in_init'] == 'True') and (dll.fields['dll_in_mem'] == 'True'):
                yield "%s (pid: %s) may be hidden." % (dll.fields['dll_mapped_path'], dll.fields['process_id'])
 

def sid_warnings(sids, envars):

    # Do we see domain admin privs?
    for sid in sids:
        if 'domain' in sid.fields['sid_name'].lower() or 'enterprise' in sid.fields['sid_name'].lower():
            yield "%s (pid: %s) has %s rights." % (sid.fields['filename'], sid.fields['process_id'], sid.fields['sid_name'])


def handle_warnings(handles, envars):

    for handle in handles:
        if '\\Device\\RawIp\\0' in handle.fields['name']:
            yield "%s (pid: %s) has a raw socket handle." % (sid.fields['filename'], sid.fields['process_id'], sid.fields['sid_name'])


def privilege_warnings(privs, envars):

    for priv in privs:
        if 'debug' in priv.fields['privilege'].lower():
            if priv.fields['present'] == 'True' and  priv.fields['enabled'] == 'True' and priv.fields['the_default'] == 'False':
                yield "%s (pid: %s) has privilege %s present and enabled, not default." % (priv.fields['filename'], priv.fields['process_id'], priv.fields['privilege'])


def mftentry_warnings(mftentries, envars):

    for entry in mftentries:
        if "DATA ADS" in entry.fields['name']:
            yield "File: %s has an ADS." % (entry.fields['name'])


def callback_warnings(callbacks, envars):

    for cb in callbacks:
        if 'unknown' in cb.fields['module'].lower():
            yield "Possible malicious callback: %s %s %s %s." % (cb.fields['type'], cb.fields['callback'], cb.fields['module'], cb.fields['detail'])


def timer_warnings(timers, envars):

    for timer in timers:
        if 'unknown' in timer.fields['module'].lower():
            yield "Possible malicious timer: %s %s %s %s %s." % (timer.fields['due_time'], timer.fields['period'], timer.fields['signaled'], timer.fields['routine'], timer.fields['module'])


def module_warnings (modules, envars):

    for mod in modules:
        if temp(mod.fields['full_dll_name']):
            yield "Module %s has temp in path." % (mod.fields['full_dll_name'])


def check_warnings(plugins, db):
    
    import db_ops
    db_ops = db_ops.DBOps()

    yield "\nWarnings: (Experimental)"
    
    # Get table names from db
    tables = db_ops.get_tables(db)

    # Get profile from db
    envars = db_ops.get_meta(db)

    # For each table in the db
    for table in tables:

        if table == 'META':
            continue

        # Get the plugin name and setobj name for this db table 
        plug_name, setobj_name = table.split('_')
        # Import the plugin module
        plug = __import__(plug_name)
        # Get a setobj object
        setobj = getattr(plug, setobj_name)()

        # Get the db rows for this table back into objects
        memobjs = []
        for row in db_ops.get_rows(db, table):
            memobjs.append(setobj.memobj_from_row(row))

        # If we have warnings to check, then do it    
        if plug_name in memobj_warning_funcs.keys():
            yield "\nChecking: %s" % plug_name
            for elem in memobj_warning_funcs[plug_name](memobjs, envars):
                yield elem    
    
    yield "\nDone."



memobj_warning_funcs = { 'processes' : process_warnings,
                        'injections' : injection_warnings,
                        'dlls'       : dll_warnings,
                        'privileges' : privilege_warnings,
                        'sids'       : sid_warnings,
                        'handles'    : handle_warnings,
                        'mftentries' : mftentry_warnings,
                        'callback'   : callback_warnings,
                        'timers'     : timer_warnings, 
                        'modules'    : module_warnings }

