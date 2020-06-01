import services
from collections import defaultdict
from random import shuffle

class serviceScanner():
    """Class for Light Service Enumeration"""
    def __init__(self,info):
        self.address = info[0]
        self.ports = info[1]
        self.results = defaultdict(list)
        shuffle(self.ports)
        self.enumerators = services.enumerators
        self.unknownports = []

    def start(self):
        """Runs serviceScanner object"""
        for port in self.ports:
            if self.enumerators[port] != 0:
                self.results[port].append(self.enumerators[port](self.address,port))
        return self.results

if __name__ == "__main__":
    test = serviceScanner(('10.10.10.107',[445, 80, 22]))
    test.start()
    print(test.results)