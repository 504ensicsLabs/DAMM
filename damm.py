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

import sys, os
from libdamm.api import API as DAMM
import tempfile


def parse_args(argv):

    import argparse
    parser = argparse.ArgumentParser(description='DAMM v1.0 Beta')
    parser.add_argument('-d', help='Path to additional plugin directory', metavar='DIR')
    parser.add_argument('-p', nargs='+', help='Plugin(s) to run. For a list of options use --info', metavar='PLUGIN')
    parser.add_argument('-f', help='Memory image file to run plugin on', metavar='FILE')
    parser.add_argument('-k', help='KDBG address for the images (in hex)', metavar='KDBG')
    parser.add_argument('--db', help='SQLite db file, for efficient input/output') 
    parser.add_argument('--profile', help='Volatility profile for the images (e.g. WinXPSP2x86)')
    parser.add_argument('--debug', help='Print debugging statements', action='store_true')
    parser.add_argument('--info', help='Print available volatility profiles, plugins', action='store_true')
    parser.add_argument('--tsv', help='Print screen formatted output.', action='store_true')
    parser.add_argument('--grepable', help='Print in grepable text format', action='store_true')
    parser.add_argument('--filter', help='Filter results on name:value pair, e.g., pid:42')
    parser.add_argument('--filtertype', help='Filter match type; either "exact" or "partial", defaults to partial')
    parser.add_argument('--diff', help='Diff the imageFile|db with this db file as a baseline', metavar='BASELINE')
    parser.add_argument('-u', nargs='+', help='Use the specified fields to determine uniqueness of memobjs when diffing', metavar='FIELD')
    parser.add_argument('--warnings', help='Look for suspicious objects.', action='store_true')
    parser.add_argument('-q', help='Query the supplied db (via --db).', action='store_true')

    return parser.parse_args()


def main(argv=None):
    '''
    
    '''
    args = parse_args(argv)

    damm = DAMM(plugins=args.p, extra_dir=args.d, memimg=args.f, profile=args.profile, kdbg=args.k, debug=args.debug, filterp=args.filter, filterp_type=args.filtertype, db=args.db, unique_id_fields=args.u, diff=args.diff)

    if args.info:
        print damm.vol_profiles_info()
        print damm.loaded_plugins_info()
        sys.exit()

    if args.q:
        if not args.db:
            print 'You must specify a db to query.'
            sys.exit()

        if not os.path.isfile(args.db):
            print "%s is not a file." % args.db     
            sys.exit()

        envars, tables = damm.query_db()
        for name, val in envars:
            if name.lower() in ['profile', 'memimg', 'computername']:
                print "%s:\t%s" % (name, val)
        print "plugins:\t%s" % " ".join([x.split("_")[0] for x in tables if x != 'META'])     
        sys.exit()


    if args.warnings:
        warns = damm.check_warnings(damm.get_plugins(), args.db)
        for elem in warns:
            print elem
        sys.exit()    


    if args.p is None:
        print "You must specify plugins to run."
        sys.exit()

    # if --filter, must be blah:blah
    if args.filter:
        if len(args.filter.split(":")) != 2:
            print 'Filter must be in type:value format, e.g., pid:4.'
            sys.exit()
    
    # if --filtertype, must be 'partial' or 'exact' and have --filter
    if args.filtertype:
        if not args.filter:
            print 'Filtertype requires the --filter argument.'
            sys.exit()
        if args.filtertype.lower() != 'partial' and args.filtertype.lower() != 'exact':
            print 'Filtertype must be one of either \'partial\' or \'exact\'.'
            sys.exit() 

    if args.diff:
        if not args.db:
            print 'Diff requires the --db argument.'
            sys.exit()
        
        # exists(--diff) 
        if not os.path.isfile(args.diff):
            print '%s does is not a file.' % args.diff
            sys.exit()  

        # exists(--db)    
        if not os.path.isfile(args.db):
            print '%s does is not a file.' % args.db
            sys.exit()  

        if args.grepable:
            results = damm.do_diffs_grepable()
        elif args.tsv:
            results = damm.do_diffs_tsv()
        else:
            results = damm.do_diffs_screen()

        for elem in results:
            print elem

    else: # no diff

        # require at least one of -f or --db
        if not args.f and not args.db:
            print "You must specify an image file or a DAMM db."
            sys.exit()

        if args.f and not os.path.isfile(args.f):
            print '%s is not a file.' % args.f
            sys.exit()

        if args.u:
            print "The -u is only applicable to diff operations."
            sys.exit() 

        if args.profile:
            if args.profile not in damm.get_vol_profiles():
                print "%s is not a valid profile." % args.profile 
                sys.exit()

        kill_tempdb = False    
        if not args.db:
            tempdb = tempfile.NamedTemporaryFile()
            damm.set_db(tempdb.name)
            kill_tempdb = True

        if args.grepable:
            results = damm.run_plugins_grepable()
        elif args.tsv:
            results = damm.run_plugins_tsv()
        else:
            results = damm.run_plugins_screen()
               
        for elem in results:
            print elem        


        if kill_tempdb:
            tempdb.close()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
