import sys


class sqlutils():

    def __init__(self, **kwargs):
        sys.bytecodebase = None
        sys.dont_write_bytecode = True
        import re
        DBTYPES_RGX = re.compile(r'(?:sqlite3|mysql|mssql|oracle|postgre)', \
            re.IGNORECASE)

        DEFAULT_PORTS = {}
        DEFAULT_PORTS['mssql'] = 1433
        DEFAULT_PORTS['mysql'] = 3306
        DEFAULT_PORTS['oracle'] = 1521
        DEFAULT_PORTS['postgre'] = 5432

        self.dbtype = None
        self.dbfile = None
        self.host = None
        self.database = None
        self.user = None
        self.passw = None
        self.port = 0

        if 'dbtype' in kwargs.keys() and kwargs['dbtype'] is not None:
            self.dbtype = kwargs['dbtype']
        else:
            # default to sqlite3
            self.dbtype = 'sqlite3'
            self.dbfile = 'scandata.db'

        if DBTYPES_RGX.search(self.dbtype) is None:
            raise ValueError("Unexpected database type: {}".format(self.dbtype))

        if 'sqlite3' in self.dbtype:
            if 'dbfile' in kwargs.keys() and kwargs['dbfile'] is not None:
                assert isinstance(kwargs['dbfile'], str), \
                    "'dbfile' must be s tring.  Got {}".format(\
                        type(kwargs['dbfile']))
                self.dbfile = kwargs['dbfile']
            elif 'dbfile' not in kwargs.keys() and self.dbfile is not None:
                # passthru to the defaults
                pass
            else:
                raise Exception("You must specify a dbfile with the 'sqlite3' dbtype.")
        else:
            if 'host' in kwargs.keys() and \
                    kwargs['host'] is not None:
                self.host = kwargs['host']
            if 'database' in kwargs.keys() and \
                    kwargs['database'] is not None:
                self.database = kwargs['database']
            if 'user' in kwargs.keys() and \
                    kwargs['user'] is not None:
                self.user = kwargs['user']
            if 'pass' in kwargs.keys() and \
                    kwargs['pass'] is not None:
                self.passw = kwargs['pass']
            if 'port' in kwargs.keys() and \
                    kwargs['port'] is not None:
                self.port = kwargs['port']
            else:
                self.port = DEFAULT_PORTS[self.dbtype]


    def dbsetup(self):
        if 'sqlite3' in self.dbtype:
            import sqlite3
            tables = {}
            tables['config'] = ("CREATE TABLE IF NOT EXISTS config ",
                            "(name TEXT, value TEXT);")
            tables['hosts'] = ("CREATE TABLE IF NOT EXISTS hosts ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "hostname TEXT NOT NULL, ",
                            "ipv4addr TEXT NOT NULL);")
            tables['services'] = ("CREATE TABLE IF NOT EXISTS services ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "name TEXT, ",
                            "status TEXT, reason TEXT);")
            tables['ports'] = ("CREATE TABLE IF NOT EXISTS ports ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
                            "port_num INTEGER);")
            tables['found'] = ("CREATE TABLE IF NOT EXISTS found ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "host_id INTEGER NOT NULL, ",
                            "service_id INTEGER NOT NULL, ",
                            "first_found INTEGER, last_found INTEGER, ",
                            "scan_count INTEGER NOT NULL);")
            tables['vulns'] = ("CREATE TABLE IF NOT EXISTS vulns ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "name TEXT NOT NULL);")
            tables['vulns_found'] = ("CREATE TABLE IF NOT EXISTS vulns_found ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "host_id INTEGER NOT NULL, ",
                            "service_id INTEGER NOT NULL, ",
                            "vuln_id INTEGER NOT NULL, ",
                            "first_found INTEGER NOT NULL, ",
                            "last_found INTEGER NOT NULL);")
            tables['times'] = ("CREATE TABLE IF NOT EXISTS times ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "datetime INTEGER, script_name TEXT, ",
                            "script_args TEXT, start_time INTEGER, ",
                            "end_time INTEGER, diff INTEGER, ",
                            "avg_atom_time DOUBLE);")
            tables['http_meta'] = ("CREATE TABLE IF NOT EXISTS http_meta ",
                            "(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ",
                            "service TEXT, ip_addr TEXT, ",
                            "server_header TEXT, ",
                            "header_first_found INTEGER, ",
                            "header_last_updated INTEGER, ",
                            "html_title TEXT, title_first_found INTEGER, ",
                            "title_last_updated INTEGER);")
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            for k,v in tables.items():
                #print("{}".format("".join(v)))
                c.execute("".join(v))
            conn.commit()
            conn.close()
        else:
            print("Don't know how to handle database type ({}) yet.".format( \
                self.dbtype))
            exit(1)


    def load_config(self):
        config = {}
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            for row in c.execute("SELECT * FROM config;"):
                config[row[0]] = row[1]
            conn.close()
        else:
            raise Exception("Don't know how to handle dbtype: {}".format( \
                self.dbtype))
        return config


    def _get_record_id(self, table, field, value, **kwargs):
        if 'sqlite3' in self.dbtype:
            import sqlite3
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))


    def _record_exists(self, table, field, value):
        print("|{}|".format(value))
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            # parameterized queries allows the SQL driver to translate
            # None to NULL.  (Even tho it should never be None.)
            sql = "SELECT id FROM {tn} WHERE {fn}=?"\
                    .format(tn=table, fn=field)
            try:
                c.execute(sql, (value,))
            except sqlite3.OperationalError as err:
                if 'table not found' in str(err):
                    print("You need to run dbsetup() prior to checking if a record exists.")
                    exit(1)
                else:
                    raise err
            result = c.fetchone()
            if result:
                print(result)
                return result[0]
            else:
                return False
            conn.close()
        else:
            print("Don't know how to handle dbtype {} yet.".format(self.dbtype))


    def ip_exists(self, ipaddr):
        return self._record_exists('hosts', 'ipv4addr', ipaddr)


    def host_exists(self, name):
        return self._record_exists('hosts', 'hostname', name)


    def port_exists(self, port):
        return self._record_exists('ports', 'port_num', port)


    def _record_exists_2f(self, table, field, value, field2, value2):
        sys.dont_write_bytecode = True
        print("|{}-{}|".format(value, value2))
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            # parameterized queries allows the SQL driver to translate
            # None to NULL.  (Even tho it should never be None.)
            sql = "SELECT id FROM {tn} WHERE {fn}=? AND {f2}=?"\
                    .format(tn=table, fn=field, f2=field2)
            try:
                c.execute(sql, (value,value2))
            except sqlite3.OperationalError as err:
                if 'table not found' in str(err):
                    print("You need to run dbsetup() prior to checking if a record exists.")
                    exit(1)
                else:
                    raise err
            result = c.fetchone()
            if result:
                print(result)
                return result[0]
            else:
                return False
            conn.close()
        else:
            print("Don't know how to handle dbtype {} yet.".format(self.dbtype))


    def found_exists(self, host, port):
        sys.dont_write_bytecode = True
        return self._record_exists_2f('found',
            'host_id', self.get_host_id(host),
            'service_id', self.get_port_id(port))


    def get_port_id(self, port):
        sys.dont_write_bytecode = True
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            c.execute("SELECT id FROM ports WHERE port_num=?", \
                (port,))
            res = c.fetchone()
            print("|{}|".format(res))
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))
        if res:
            return int(res[0])
        else:
            return None


    def get_host_id(self, host):
        sys.dont_write_bytecode = True
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            c.execute("SELECT id FROM hosts WHERE ipv4addr=? OR hostname=?", \
                (host,host))
            res = c.fetchone()
            print("|{}|".format(res))
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))
        if res:
            return int(res[0])
        else:
            return None


    def get_found_id(self, host, port):
        sys.dont_write_bytecode = True
        host_id = self.get_host_id(host)
        port_id = self.get_port_id(port)
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "SELECT id FROM found WHERE host_Id=? AND service_id=?"
            c.execute(sql, (host_id, port_id))
            res = c.fetchone()
            print("|{}|".format(res))
            conn.close()
        else:
            raise Exception("Don't know how to handle db type {}".format( \
                self.dbtype))
        if res:
            return int(res[0])
        else:
            return None


    def _insert_record(self, table, fields):
        assert isinstance(fields, dict), \
            "The fields parameter should be a dict of field/value pairs to insert."
        if 'sqlite3' in self.dbtype:
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "INSERT INTO {tn} ( ".format(tn=table)
            sql += ",".join(fields.keys())
            sql += " ) VALUES ( '"
            sql += "','".join([str(x) for x in fields.values()])
            sql += "' );"
            print(sql)
            c.execute(sql)
            conn.commit()
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))


    def add_host(self, host_dict):
        self._insert_record('hosts', host_dict)


    def add_port(self, port_dict):
        self._insert_record('ports', port_dict)


    def add_found(self, found_dict):
        self._insert_record('found', found_dict)


    def _update_record(self, table, fields, conds):
        assert isinstance(fields, tuple), \
            "The fields parameter should be a tuple of field/value pairs to update."
        assert isinstance(conds, tuple), \
            "The conds parameter should be a tuple of condition/value pairs."
        if 'sqlite3' in self.dbtype:
            num_conds = len(conds)
            if num_conds % 2 != 0:
                errstr = "Unbalanced key/value pairs in conds:\n"
                errstr += str(conds)
                raise Exception(errstr)
            import sqlite3
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "UPDATE {tn} SET {f}={fv} ".format( \
                tn=table, f=fields[0], fv=fields[1])
            if num_conds == 2:
                sql += "WHERE {c}={cv};".format( \
                    c=conds[0], cv=conds[1])
                print(sql)
            elif num_conds == 4:
                sql += "WHERE {c}='{cv}' AND {c2}='{cv2}';".format( \
                    c=conds[0], cv=conds[1], \
                    c2=conds[2], cv2=conds[3])
                print(sql)
            else:
                raise Exception("Don't know how to handle more then 2 conditions yet.")
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))


    def update_found(self, fields, conds):
        return self._update_record('found', fields, conds)


    def _get_scan_count(self, host, port):
        sys.dont_write_bytecode = True
        if 'sqlite3' in self.dbtype:
            import sqlite3
            hid = self.get_host_id(host)
            pid = self.get_port_id(port)
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "SELECT scan_count FROM found WHERE host_id=? AND service_id=?;"
            c.execute(sql, (hid, pid))
            count = int(c.fetchone()[0])
            conn.close()
            return count
        else:
            raise Exception("Don't know how to handle db type: {}".format( \
                self.dbtype))


    def _increment_scan_count(self, host, port):
        sys.dont_write_bytecode = True
        if 'sqlite3' in self.dbtype:
            import sqlite3
            hid = self.get_host_id(host)
            pid = self.get_port_id(port)
            conn = sqlite3.connect(self.dbfile)
            c = conn.cursor()
            sql = "SELECT scan_count FROM found WHERE host_id=? AND service_id=?;"
            c.execute(sql, (hid, pid))
            res = c.fetchone()
            if res is not None:
                count = int(res[0])
            else:
                count = 0
            count += 1
            sql = "UPDATE found SET scan_count=? WHERE host_id=? AND service_id=?;"
            c.execute(sql, (count, hid, pid))
            conn.commit()
            conn.close()
        else:
            raise Exception("Don't know how to handle db type: {}".format(
                self.dbtype))
