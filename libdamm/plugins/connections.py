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
# A plugin for dealing with network connections from Windows memory dumps.
#

import libdamm.memory_object as memobj


def getPluginObject(vol):
    return ConnectionSet(vol)

def getFields():
    return Connection().get_field_keys()


class ConnectionSet(memobj.MemObjectSet):
    '''
    Manages sets of network  sockets/connections from Windows memory dumps.
    '''

    @staticmethod
    def get_field_typedefs():
        defs = {}
        defs['pid'] = ['pid']
        defs['ip'] = ['local_ip', 'remote_ip']
        defs['port'] = ['local_port', 'remote_port']
        return defs


    @staticmethod
    def is_XP_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)


    @staticmethod
    def is_post_XP_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 6)


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)


    def get_all(self):

        import volatility.utils as utils
        addr_space = utils.load_as(self.vol.config)       

        elems = {}
        for elem in self.get_scan():
            elems[self.get_unique_id(elem)] = elem
        for elem in self.get_alloc(addr_space):
            elems[self.get_unique_id(elem)] = elem

        value = None
        for _, v in elems.items():
            yield v


    def get_alloc(self, addr_space):
        '''
        Mimics volatility's connections, sockets. and netscan plugins.
        '''
        import volatility.utils as utils
        addr_space = utils.load_as(self.vol.config)      

        if self.is_post_XP_profile(addr_space.profile):
            # mimic Volatility netscan
            import volatility.plugins.netscan as netscan
            import volatility.utils as utils

            nscan = netscan.Netscan(self.vol.config)
            for net_object, proto, laddr, lport, raddr, rport, state in nscan.calculate(): 
                #yield Connection(net_object, proto, laddr, lport, raddr, rport, state, )
                yield Connection(hex(net_object.obj_offset), str(net_object.Owner.UniqueProcessId), str(laddr), str(lport), str(raddr), str(rport), str(proto), '', str(state), str(net_object.CreateTime), str(net_object.Owner.ImageFileName))


        elif self.is_XP_profile(addr_space.profile):        

            import volatility.plugins.connections as connections
            for tcp_obj in connections.Connections(self.vol.config).calculate():
                #yield Connection(conn, True, self.get_offset(conn, True))
                yield Connection(self.get_offset(tcp_obj), str(tcp_obj.Pid), str(tcp_obj.LocalIpAddress), str(tcp_obj.LocalPort), str(tcp_obj.RemoteIpAddress), str(tcp_obj.RemotePort), '', '', '', '', '', 'True')


            import volatility.win32.network as network
            import volatility.protos as protos
            for sock in network.determine_sockets(addr_space):
                #yield Connection(sock, True, self.get_offset(sock, True))
                yield Connection(offset=self.get_offset(sock), pid=str(sock.Pid), local_ip=str(sock.LocalIpAddress), local_port=str(sock.LocalPort), proto=str(protos.protos.get(sock.Protocol.v(), "-")), protocol=str(sock.Protocol), created=str(sock.CreateTime), allocated='True')

        else:
            import sys
            sys.stderr.write("connections plugin does not support %s\n" % self.vol.config.get_value('profile'))
                

   
    def get_scan(self):
        '''
        Mimics volatility's connscan, sockscan plugin.
        '''
        import volatility.utils as utils
        addr_space = utils.load_as(self.vol.config)      

        if self.is_post_XP_profile(addr_space.profile):
            # mimic Volatility netscan
            pass

        elif self.is_XP_profile(addr_space.profile):        

            import volatility.plugins.connscan as connscan
            for tcp_obj in connscan.ConnScan(self.vol.config).calculate():
                yield Connection(self.get_offset(tcp_obj), str(tcp_obj.Pid), str(tcp_obj.LocalIpAddress), str(tcp_obj.LocalPort), str(tcp_obj.RemoteIpAddress), str(tcp_obj.RemotePort), '', '', '', '', '', 'False')

            import volatility.plugins.sockscan as sockscan
            import volatility.protos as protos
            for sock in sockscan.SockScan(self.vol.config).calculate():
                yield Connection(offset=self.get_offset(sock), pid=str(sock.Pid), local_ip=str(sock.LocalIpAddress), local_port=str(sock.LocalPort), proto=str(protos.protos.get(sock.Protocol.v(), "-")), protocol=str(sock.Protocol), created=str(sock.CreateTime), allocated='False')


    def get_child(self):
        return Connection()


    def get_unique_id(self, conn):    
        return (conn.fields['pid'], conn.fields['local_ip'], conn.fields['local_port'], conn.fields['remote_ip'], conn.fields['remote_port'], conn.fields['proto'], conn.fields['protocol'], conn.fields['created'], conn.fields['owner'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: 0 if x.fields['pid'] == '' else int(x.fields['pid']))
        return elems


class Connection(memobj.MemObject):

    def __init__(self, offset='', pid='', local_ip='', local_port='', remote_ip='', remote_port='', proto='', protocol='', state='', created='', owner='', allocated=''):

        memobj.MemObject.__init__(self, offset)
        
        self.fields['pid'] = pid
        self.fields['local_ip'] = local_ip
        self.fields['local_port'] = local_port
        self.fields['remote_ip'] = remote_ip
        self.fields['remote_port'] = remote_port
        self.fields['proto'] = proto
        self.fields['protocol'] = protocol
        self.fields['state'] = state
        self.fields['created'] = created
        self.fields['owner'] = owner
        self.fields['allocated'] = allocated
