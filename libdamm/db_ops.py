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

import sqlite3
from utils import debug
from utils import err
import plugin
import sys


class DBOps:

    def __init__(self):
        pass


    def get_tables(self, db):
        '''
        Get table names from a db.

        @db: a DAMM db

        @return: list of string names of db tables 
        '''
        conn = sqlite3.connect(db)
        curs = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        res = [str(x[0]) for x in curs.fetchall()]
        conn.close()

        return res


    def get_rows(self, db, table):
        '''
        Get rows from a db table.

        @db: a DAMM db
        @table: string name of table to get rows from

        @return: list of db rows
        '''
        conn = sqlite3.connect(db)
        curs = conn.execute('select * from %s' % table)
        rows = curs.fetchall()
        conn.close()

        return rows


    def db_empty(self, db):
        '''
        Is the db empty?
        '''
        return self.get_tables(db) == []


    def in_db(self, db, table_name):
        '''
        Is the specified table in the specified db.
        '''
        conn = sqlite3.connect(db)
        res = False
        if table_name in self.get_tables(db):
            res = True
        conn.close()

        return res


    def init_db(self, db, memimg, profile, env):
        '''
        If this is a new db, store some metadata: filename of the originating
        memory image, and the profile for the image.
        '''
        conn = sqlite3.connect(db)
        cmd = "create table META (varname text, varval text)"
        debug(cmd)
        conn.execute(cmd)
        cmd = 'insert into META values(?, ?)'
        fields = ('profile', profile)
        conn.execute(cmd, fields)
        fields = ('memimg', memimg)
        conn.execute(cmd, fields)
        for var, val in env:
            fields = (var, val)
            conn.execute(cmd, fields)
        conn.commit()
        conn.close()


    def get_meta(self, db):
        '''
        Return the filename, profile and set of tables stored in the db. 
        '''
        return self.get_rows(db,'META')


    def get_table_name(self, setobj):
        '''
        Return the proper talbe name for the given memobj type.
        '''
        return "%s_%s" % (setobj.__module__, setobj.__class__.__name__)


    def create_table(self, conn, setobj):
        '''
        Create a new db table for the specified memobj type.
        '''
        command = "create table %s (" % (self.get_table_name(setobj))
        for elem in setobj.get_child().fields.keys():
            command += "%s text," % elem
        command = command.rstrip(",") + ")"
        debug(command)
        conn.execute(command)


    def __insert_into_table(self, conn, memobj, setobj):
        '''
        Insert a single memobj into a db.
        '''
        fields = tuple([memobj.fields[field] for field in memobj.fields.keys()])
        qms = "?"
        for x in xrange(len(fields) - 1):
            qms += ",?"
        cmd = 'insert into %s values(%s)' % (self.get_table_name(setobj), qms)
        debug("cmd: %s\nfields: %s\ntypes: %s" % (cmd, fields, str([type(x) for x in fields])))
        conn.execute(cmd, fields)



    def insert_plugin(self, setobj, db, memimg):
        '''
        Run plugin against memimg and insert into db.

        @setobj: memobj set object, e.g., ProcessSet
        @conn: connection to the databse use

        '''
        conn = sqlite3.connect(db)
        self.create_table(conn, setobj)

        for elem in setobj.analyze_file(memimg):  # run plugin on file
            self.__insert_into_table(conn, elem, setobj)
            debug("Inserted %s into %s" % (str(elem), str(conn)))

        conn.commit()
        conn.close()
