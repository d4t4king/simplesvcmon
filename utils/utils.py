import os

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
        from scapy.all import sr, srp, IP, UDP, ICMP, TCP, ARP, Ether
        ans, unans = sr(IP(dst=host)/ICMP(), retry=0, timeout=1)
        print("ans: {a}, unans: {u}".format(a=ans, u=unans))
        if ans is not None:
            return True
        else:
            return False


    @staticmethod
    def cleanup(file):
        ###	clean up
        os.remove(file)
