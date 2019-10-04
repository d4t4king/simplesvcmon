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
