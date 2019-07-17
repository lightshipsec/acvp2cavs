import json
import sys
import time
from pdb import set_trace as bp
from cavsalg import CAVSAlgorithm

def all_zeros(tc, field):
    return tc[field].count('0') == len(tc[field])

def bitpatterns(tc, field):
    # Returns set of representation and number of zeros found
    bits = set(tc[field])
    zeros = tc[field].count('0')
    return bits, zeros

def is_multiblock_test(tg):
    keylens = 0
    outlens = 0
    for tc in tg["tests"]:
        keylens += len(tc['key'])
        if 'ct' in tc:
            outlens += len(tc['ct'])
        elif 'pt' in tc:
            outlens += len(tc['pt'])
    # Averages
    return keylens/len(tg) < outlens/len(tg)


def well_represented(tg, field):
    all_zeros = 0
    all_bits = set([])
    for tc in tg["tests"]:
        bits, zeros = bitpatterns(tc, field)
        all_bits = all_bits.union(bits)
        all_zeros += zeros

    # Ensure that if it is not well represented, this doesn't mean the same as 'zero'
    if all_bits == set([0]):
        return False

    if len(all_bits) <= 8 and all_zeros > len(tg["tests"]):
        return False
    return True


class AES(CAVSAlgorithm):
    def __init__(self, mode):
        self._mode = mode
        super(AES, self).__init__("AES-%s" % self._mode)

    def legacy_file_groups(self):
        """Legacy file groups are <mode><function><keysize>
        These details are scattered throughout the vector set and we need to recapture them.
        Mode is already known.
        Return a list of the filenames along with the grouping criteria needed to generate them.
        """
        filegroups = []
        for subType in self._indexes['_testSubType']:
            for tg in self._indexes['_testSubType'][subType]:
                filegroups.append({
                    "filename": '%s%s%s.req' % (self._mode, subType, tg['keyLen']),
                    "testGroups": 
                        self.findAll(self.testGroups, {"keyLen": tg['keyLen'], "_testSubType": subType})
                })

        return filegroups

    def generate_legacy_group_record(self, group):
        return "[" + group['direction'].upper() + "]"

    def generate_legacy_test_case_record(self, group, test):
        if group['direction'] == 'encrypt':
            text = "PLAINTEXT = %s" % test['pt'].lower()
        else:
            text = "CIPHERTEXT = %s" % test['ct'].lower()

        # Counter is zero-based in CAVS and ACVP test case IDs don't actually
        # guarantee to start from zero.
        count = int(test['tcId']) - int(group['tests'][0]['tcId'])

        res = """COUNT = {count}
KEY = {key}
""".format(count=count, key=test['key'].lower())
        if 'iv' in test:
            res += "IV = {iv}\n".format(iv=test['iv'].lower())
        res += "{text}".format(text=text)

        return res


    def generate_legacy_header(self, groups, py_timestamp):
        """Generate a legacy header.
        Parameter is a timestamp as a python object."""

        # I want 'Encrypt and Decrypt' or 'Encrypt' or 'Decrypt'
        # I have tried a variety of list comprehensions and set functions and they all aren't
        # totally correct or readable.  This is correct and readable.
        encrypt = self.findAll(groups, {'direction': 'encrypt'})
        decrypt = self.findAll(groups, {'direction': 'decrypt'})
        if encrypt and decrypt:
            states = 'Encrypt and Decrypt'
        elif encrypt:
            states = 'Encrypt'
        else:
            states = 'Decrypt'

        header = """# CAVS 21.4
# Config info for TBD
# AESVS {function} test data for {mode}
# State : {states}
# Key Length : {key_len}
# Generated on {ctime}""".format(mode=self._mode, function=groups[0]['_testSubType'], states=states, key_len=groups[0]['keyLen'], ctime=time.ctime(py_timestamp))
        return header

        

    def detect_test_sub_type(self, tg):
        if tg["testType"] != 'AFT':
            return tg["testType"].upper()

        print "%s %s" % (self.algorithm, tg['tgId'])
        for tc in tg["tests"]:
            if tg["testType"] == "AFT":
                if tg["direction"] == "encrypt":
                    # These rules are basically the same except for ECB (no IV) and CFB1
                    # (which has different rules).
                    # Notice that 'well-represented' is against the test GROUP and all-zeros
                    # is against the individual test case.  well-represented is more of an
                    # average consideration over the entire test group.
                    if not all_zeros(tc, 'iv') and not all_zeros(tc, "key") and not all_zeros(tc, "pt"):
                        return "MMT"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'pt') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'key') and well_represented(tg, 'pt'):
                        return "GFSbox"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'pt') and not well_represented(tg, 'key'):
                        return "VarKey"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'key') and not well_represented(tg, 'pt'):
                        return "VarTxt"
                    else:
                        raise RuntimeError("Unknown test type in encrypt")
            
                else:
                    if not all_zeros(tc, 'iv') and not all_zeros(tc, "key") and not all_zeros(tc, "ct"):
                        return "MMT"
                    elif all_zeros(tc, 'iv') and well_represented(tg, 'ct') and well_represented(tg, 'key'):
                        return "KeySbox"
                    # This is a special case due to ambiguity of ciphertext being well-represented in both cases of GFSBox and VarTxt
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'key') and well_represented(tg, 'ct') and len(tg["tests"]) < 100:
                        return "GFSbox"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'key') and well_represented(tg, 'ct'):
                        return "VarTxt"
                    elif all_zeros(tc, 'iv') and not well_represented(tg, "key") and well_represented(tg, 'ct'):
                        return "VarKey"
                    else:
                        raise RuntimeError("Unknown test type in decrypt")



class AESCFB(AES):
    def __init__(self, bits):
        super(AESCFB, self).__init__("CFB%s" % bits)

    def detect_test_sub_type(self, tg):
        if tg["testType"] != 'AFT':
            return tg["testType"].upper()

        print "%s %s" % (self.algorithm, tg['tgId'])
        for tc in tg["tests"]:
            if tg["testType"] == "AFT":
                if tg["direction"] == "encrypt":
                    if well_represented(tg, 'key') and well_represented(tg, 'iv'):
                        return "MMT"
                    elif all_zeros(tc, 'iv') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif all_zeros(tc, 'key') and well_represented(tg, 'iv'):
                        return "GFSbox"
                    elif all_zeros(tc, 'iv') and not well_represented(tg, 'key'):
                        return "VarKey"
                    elif all_zeros(tc, 'key') and not well_represented(tg, 'iv'):
                        return "VarTxt"
                    else:
                        raise RuntimeError("Unknown test type in encrypt")
            
                else:
                    if well_represented(tg, 'iv') and well_represented(tg, "key"):
                        return "MMT"
                    elif well_represented(tg, 'iv') and all_zeros(tc, "key"):
                        return "GFSbox"
                    elif all_zeros(tc, 'iv') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif all_zeros(tc, 'key') and not well_represented(tg, 'iv'):
                        return "VarTxt"
                    elif all_zeros(tc, 'iv') and not well_represented(tg, "key"):
                        return "VarKey"
                    else:
                        raise RuntimeError("Unknown test type in decrypt")


    def generate_legacy_test_case_record(self, group, test):
        """CFB1 will output as binary bits. Which is super annoying.
        I have no idea what the relationship between payloadLen and the CT/PT is.
        Based on CAVS output and NIST 800-38A, it *appears* that it is the numbre
        of bits in the CT/PT which are actually subjected to the cipher. The
        remaining bits are simply thrown away.  Thus, we generate a variable-sized
        bitmask based on the payloadLen, then mask those bits from the PT/CT."""
        if group['direction'] == 'encrypt':
            if self._mode.lower() == 'cfb1':
                text = "PLAINTEXT = {pt:0{width}b}".format(
                    pt=int(test['pt'], 16) & int("0b"+('1'*(int(test['payloadLen']))),2),
                    width=int(test['payloadLen'])
                )
            else:
                text = "PLAINTEXT = {pt}".format(pt=test['pt'].lower())
        else:
            if self._mode.lower() == 'cfb1':
                text = "CIPHERTEXT = {ct:0{width}b}".format(
                    ct=int(test['ct'], 16) & int("0b"+('1'*(int(test['payloadLen']))),2),
                    width=int(test['payloadLen'])
                )
            else:
                text = "CIPHERTEXT = {ct}".format(ct=test['ct'].lower())

        # Counter is zero-based in CAVS and ACVP test case IDs don't actually
        # guarantee to start from zero.
        count = int(test['tcId']) - int(group['tests'][0]['tcId'])

        res = """COUNT = {count}
KEY = {key}
""".format(count=count, key=test['key'].lower())
        if 'iv' in test:
            res += "IV = {iv}\n".format(iv=test['iv'].lower())
        res += "{text}".format(text=text)

        return res



class AESECB(AES):
    def __init__(self):
        super(AESECB, self).__init__("ECB")

    def detect_test_sub_type(self, tg):
        if tg["testType"] != 'AFT':
            return tg["testType"].upper()

        print "%s %s" % (self.algorithm, tg['tgId'])
        for tc in tg["tests"]:
            if tg["testType"] == "AFT":
                if tg["direction"] == "encrypt":
                    if is_multiblock_test(tg):
                        return "MMT"
                    elif all_zeros(tc, 'pt') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif all_zeros(tc, 'key') and well_represented(tg, 'pt'):
                        return "GFSbox"
                    elif all_zeros(tc, 'pt') and not well_represented(tg, 'key'):
                        return "VarKey"
                    elif all_zeros(tc, 'key') and not well_represented(tg, 'pt'):
                        return "VarTxt"
                    else:
                        raise RuntimeError("Unknown test type in encrypt")
            
                else:
                    if is_multiblock_test(tg):
                        return "MMT"
                    # This is a special case due to ambiguity of ciphertext being well-represented in both cases of GFSBox and VarTxt
                    elif well_represented(tg, 'ct') and all_zeros(tc, "key") and len(tg["tests"]) < 100:
                        return "GFSbox"
                    elif well_represented(tg, 'ct') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif all_zeros(tc, 'key') and well_represented(tg, 'ct'):
                        return "VarTxt"
                    elif well_represented(tg, 'ct') and not well_represented(tg, "key"):
                        return "VarKey"
                    else:
                        raise RuntimeError("Unknown test type in decrypt")



class AESOFB(AES):
    def __init__(self):
        super(AESOFB, self).__init__("OFB")

    def detect_test_sub_type(self, tg):
        if tg["testType"] != 'AFT':
            return tg["testType"].upper()

        print "%s %s" % (self.algorithm, tg['tgId'])
        for tc in tg["tests"]:
            if tg["testType"] == "AFT":
                if tg["direction"] == "encrypt":
                    if is_multiblock_test(tg):
                        return "MMT"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'pt') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif well_represented(tg, 'iv') and all_zeros(tc, 'key') and all_zeros(tc, 'pt'):
                        return "GFSbox"
                    elif all_zeros(tc, 'iv') and all_zeros(tc, 'pt') and not well_represented(tg, 'key'):
                        return "VarKey"
                    elif not well_represented(tg, 'iv') and all_zeros(tc, 'key') and all_zeros(tc, 'pt'):
                        return "VarTxt"
                    else:
                        raise RuntimeError("Unknown test type in encrypt")
            
                else:
                    if is_multiblock_test(tg):
                        return "MMT"
                    elif all_zeros(tc, 'iv') and well_represented(tg, 'ct') and well_represented(tg, 'key'):
                        return "KeySbox"
                    elif well_represented(tg, 'iv') and all_zeros(tc, 'key') and well_represented(tg, 'ct'): 
                        return "GFSbox"
                    elif not well_represented(tg, 'iv') and all_zeros(tc, 'key') and well_represented(tg, 'ct'):
                        return "VarTxt"
                    elif all_zeros(tc, 'iv') and not well_represented(tg, "key") and well_represented(tg, 'ct'):
                        return "VarKey"
                    else:
                        raise RuntimeError("Unknown test type in decrypt")


class AESCTR(AES):
    def __init__(self):
        super(AESCTR, self).__init__("CTR")

    def legacy_file_groups(self):
        filegroups = []
        for tg in self.testGroups:
            filegroups.append({
                "filename": '%s%s_%s_%s.req' % (self._mode, tg['testType'], tg['tgId'], tg['keyLen']),
                "testGroups": 
                    self.findAll(self.testGroups, {"keyLen": tg['keyLen'], "testType": tg['testType'], "tgId": tg['tgId']})
            })
        return filegroups

    def detect_test_sub_type(self, tg):
        print "%s %s" % (self.algorithm, tg['tgId'])
        return tg['testType']



if __name__ == "__main__":
    j = json.loads("\n".join(sys.stdin.readlines()))
    # To help with debugging with pdb after reading from stdin
    sys.stdin = open('/dev/tty')

    try:
        outdir = sys.argv[1]
    except IndexError:
        outdir = "."

    alg = j[1]['algorithm'][9:].upper()
    if 'CFB' in alg:
        a = AESCFB(alg[3:])
    elif 'ECB' in alg:
        a = AESECB()
    elif 'OFB' in alg:
        a = AESOFB()
    elif 'CTR' in alg:
        a = AESCTR()
    else:
        a = AES(alg)
    a.json = j
    a.to_cavs(outdir)
