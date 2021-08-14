#!/usr/bin/env python3
import sys
import plistlib
from pyasn1.type import constraint
from pyasn1.type.univ import *
from pyasn1.type.char import *
from pyasn1.type.namedtype import *
from pyasn1.type.tag import *
from pyasn1.type.opentype import *
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

class APTicketMANB(Sequence):
    componentType = NamedTypes(
        NamedType('type', IA5String()),
        NamedType('payload', Set()),
    )
    tagSet = Sequence.tagSet.tagExplicitly(
        Tag(192, 32, 1296125506)
    )
class APTicket(Sequence):
    componentType = NamedTypes(
            NamedType('type', IA5String()),
            NamedType('ver', Integer()),
            NamedType('manb', SetOf(APTicketMANB())),
            NamedType('unk', OctetString()),
            NamedType('unk2', Any())
        )

def find_build_identity(manifest, model):
    for o in manifest['BuildIdentities']:
        if o['Info']['DeviceClass'] == model and 'RestoreBehavior' in o['Info'] and o['Info']['RestoreBehavior'] == "Erase":
           return o
    return None

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(F"{sys.argv[0]} [model] [BuildManifest.plist] [ticket.shsh2] [root_ticket.der]")
        exit(1)

    model = sys.argv[1].lower()
    fd = open(sys.argv[2], "rb")
    manifest = plistlib.load(fd)
    fd.close()

    plist = find_build_identity(manifest, model)

    if plist == None:
        print(F"Cannot find {model} in BuildManifest.plist")
        exit(1)

    fd = open(sys.argv[3], "rb")
    shsh = plistlib.load(fd)
    ticket = shsh['ApImg4Ticket']
    fd.close()
    res = None
    res = decode(ticket, asn1Spec=APTicket())

    a = res[0]

    b = a['manb'][0]['payload']
    for i in range(len(b)):
        if str(b[i][0]) == 'rosi':
            b[i][1][0][1] = plist['Manifest']['OS']['Digest']
        if str(b[i][0]) == 'krnl':
            b[i][1][0][1] = plist['Manifest']['KernelCache']['Digest']
        if str(b[i][0]) == 'dtre':
            b[i][1][0][1] = plist['Manifest']['DeviceTree']['Digest']
        if str(b[i][0]) == 'rfta':
            # Corrupt this
            b[i][0] = 'atrf'
    fd = open(sys.argv[4], "wb")

    fd.write(encode(a))
    fd.close()
