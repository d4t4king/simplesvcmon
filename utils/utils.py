import os
from pprint import pprint

class utils():
    def __init__(self):
        pass


    @staticmethod
    def which(pgm):
        path = os.getenv('PATH')
        for p in path.split(os.path.pathsep):
            p = os.path.join(p, pgm)
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p


    @staticmethod
    def is_alive(host, port=None):
        from termcolor import cprint
        from scapy.all import sr1, IP, ICMP, TCP
        ans = sr1(IP(dst=host)/ICMP(), retry=0, timeout=1, verbose=False)
        if ans is not None:
            return True
        else:
            return False


    @staticmethod
    def cleanup(file):
        ###	clean up
        os.remove(file)
