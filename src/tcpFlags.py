class TCPFlags:
    def __init__(self, fin, syn, rst, psh, ack, urg):
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg