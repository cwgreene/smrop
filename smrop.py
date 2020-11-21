import subprocess

def call_ropgadget(binaryname):
    result = {}
    proc = subprocess.run(["ROPgadget", "--binary", binaryname], stdout=subprocess.PIPE)
    stdout = str(proc.stdout, "utf8")
    for line in stdout.split("\n")[2:]:
        if not line.startswith("0x"):
            continue
        addr, rops = line.split(" : ")
        rops = rops.split(" ; ")
        skip = False
        for rop in rops:
            if not rop.startswith("pop") and not rop.startswith("ret"):
                skip = True
                break
        if skip:
            continue
        rop = rops[0]
        if rop not in result:
            result[rop] = (addr, len(rops) - 1, rops)
    return result

class Smrop():
    def __init__(self, **kwargs):
        self.binaries = kwargs
        self.chain = []
        for binname in self.binaries:
            self.analyze(self.binaries[binname])

    def prefix(self, prefix):
        self.chain.append(prefix)
        return self

    def set_rdi(self, value):
        rop_addr, rop_slots, rops = self.rop["pop rdi"]
        self.chain.append(rop_addr)
        self.chain.append(value)
        for i in range(rop_slots - 1):
            self.chain.append(0)
        return self

    def ret(self, symbol_or_addr):
        addr = None
        if type(symbol_or_addr) == str:
            symbol = symbol_or_addr
            for binname in self.binaries:
                if symbol in self.binaries[binname].symobls:
                    addr = self.binaries[binname].symbols[symbol]
                    break
        else:
            addr = symbol_or_addr
        if addr is None:
            raise Exception("Cannot find symbol: {}".format(symbol))
        self.chain.append(addr)
