import subprocess
import pwn
import hashlib
import json

import os

class BinaryDb(object):
    def __init__(self):
        db = {}
        if os.path.exists("BinaryDb.json"):
            with open("./BinaryDb.json") as binarydb:
                db = json.load(binarydb)
        self.db = db

    def checkhash(self, binaryname):
        with open(binaryname, "rb") as binary:
            h = hashlib.sha256(binary.read()).hexdigest()
        return h

    def add(self, binaryname, key, metadata):
        h = self.checkhash(binaryname)
        if h not in self.db:
            self.db[h] = {}
        self.db[h][key] = metadata

    def check(self, binaryname):
        h = self.checkhash(binaryname)
        if h not in self.db:
            return False
        return True
    
    def get(self, binaryname, key):
        h = self.checkhash(binaryname)
        return self.db[h][key]

    def save(self):
        with open("./BinaryDb.json", "w") as binarydb:
            binarydb.write(json.dumps(self.db))
       
def call_ropgadget(binaryname):
    # a simple pattern match on the binary
    # would probably work fine, but I'm lazy
    # and don't want to deal with edge cases
    # or correctly loading the TEXT section.
    result = {}
    db = BinaryDb()
    if db.check(binaryname):
        return db.get(binaryname, "rops")
    
    proc = subprocess.run(["ROPgadget", "--binary", binaryname], stdout=subprocess.PIPE)
    stdout = str(proc.stdout, "utf8")
    for line in stdout.split("\n")[2:]:
        if not line.startswith("0x"):
            continue
        addr, rops = line.split(" : ")
        rops = rops.split(" ; ")
        skip = False
        for rop in rops:
            if not rop.startswith("pop") and not rop == "ret":
                skip = True
                break
        if skip:
            continue
        rop = rops[0]
        if rop not in result:
            result[rop] = (int(addr, 16), len(rops) - 1, rops)
    db.add(binaryname, "rops", result)
    db.save()
    return result

def pad(bs, align, pad_byte=b"\x00"):
    if len(bs) % align == 0:
        return bs
    rem = len(bs) % align
    bs += (align-rem)*pad_byte
    return bs

class Smrop():
    def __init__(self, **kwargs):
        self.binaries = kwargs
        self.chain = [] 
        self.rop = {}
        for bin_name in self.binaries:
            self.analyze(bin_name, self.binaries[bin_name])

    def analyze(self, bin_name, binary):
        rops = call_ropgadget(binary.path)
        for rop in rops:
            if rop not in self.rop:
                self.rop[rop] = (rops[rop], bin_name)

    def prefix(self, prefix):
        self.chain.append({"type": "blob", "value": prefix})
        return self

    def pop_rdi(self, value=None, **kwargs):
        (rop_addr, rop_slots, rops), bin_name = self.rop["pop rdi"]
        self.chain.append({"type": "offset", "value": rop_addr, "binary": bin_name})
        if value is not None:
            self.chain.append({"type": "number", "value": value})
        elif kwargs != {}:
            binary_name = list(kwargs.keys())[0]
            self.chain.append({"type": "offset", "value": kwargs[binary_name], "binary": binary_name})
            print(self.chain)
        else:
            raise Exception("Need either value or binary location")
        for i in range(rop_slots - 1):
            self.chain.append(0)
        return self

    def ret(self, symbol_or_addr, bin_name = None):
        addr = None
        if type(symbol_or_addr) == str:
            symbol = symbol_or_addr
            for bin_name in self.binaries:
                if symbol in self.binaries[bin_name].symbols:
                    addr = self.binaries[bin_name].symbols[symbol]
                    binary = bin_name
                    break
        else:
            addr = symbol_or_addr
            binary = bin_name
        if addr is None:
            raise Exception("Cannot find symbol: {}".format(symbol))
        self.chain.append({"type": "offset",
            "value": addr,
            "binary": bin_name
        })
        return self

    def nop(self):
        (rop_addr, rop_slots, rops), bin_name = self.rop["ret"]
        self.chain.append({"type": "offset", "value": rop_addr, "binary": bin_name})
        return self

    def resolve(self, **offsets):
        byte_string = b""
        for component in self.chain:
            if component["type"] == "blob":
                byte_string += component["value"]
            elif component["type"] == "number":
                c = pwn.p64(component["value"])
                byte_string += c
            elif component["type"] == "offset":
                binary_name = component["binary"]
                offset = offsets[binary_name]
                c = pwn.p64(component["value"] + offset)
                byte_string += c
        # oops, I think I messed up, I think most of this should all be
        # part of a payload object which is returend after initializing the Smrop
        self.chain = []
        return byte_string
