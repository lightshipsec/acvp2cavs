import json
import sys
import time
from pdb import set_trace as bp
from cavsalg import CAVSAlgorithm


class SHA(CAVSAlgorithm):
    def __init__(self, alg):
        if not alg.startswith('SHA'):
            raise RuntimeError("Algorithm %s is not a secure hash algorithm." % alg)

        if alg.upper() == 'SHA-1':
            alg = 'SHA1'
        elif 'SHA2-' in alg.upper():
            alg = 'SHA' + alg[5:]   # Only include the bit-size in the alg name
        elif '_' in alg:
            alg = 'SHA' + alg[5:]   # Bit size and truncation; untested in ACVP!
        else:
            raise RuntimeError("Unknown algorithm %s" % alg)

        super(SHA, self).__init__(alg)

        if alg.upper() in ('SHA1', 'SHA224', 'SHA256'):
            self._blockSize = 512
        elif alg.upper() in ('SHA384', 'SHA512', 'SHA512_224', 'SHA512_256'):
            self._blockSize = 1024
        else:
            raise RuntimeError("Unknown algorithm %s; unable to set block size" % alg)

        if alg.upper() == 'SHA1':
            self._outputSize = 160
        else:
            # We only want the END number as the output size (last 3 digits)
            self._outputSize = int(alg[-3:])

        print "Alg: %s, bs: %s, os: %s" % (alg, self._blockSize, self._outputSize)


    def legacy_file_groups(self):
        """Legacy file groups are <alg>(LongMsg|ShortMsg|Monte).req
        These details are scattered throughout the vector set and we need to recapture them.
        Alg is already known.
        Return a list of the filenames along with the grouping criteria needed to generate them.
        """
        filegroups = []
        for subType in self._indexes['_testSubType']:
            if subType != "AFT":
                filegroups.append({
                    "filename": '%s%s.req' % (self._meta['algorithm'], subType),
                    "testGroups": self._indexes['_testSubType'][subType]
                })
            else:
                for caseSubType in self._indexes['_testCaseSubType']:
                    # The conversion API expects a group to be an array of dictionary with a key called 'tests' containing an array of test cases.
                    testGroups = [{'tests': self._indexes['_testCaseSubType'][caseSubType]}]
                    filegroups.append({
                        "filename": '%s%s.req' % (self._meta['algorithm'], caseSubType),
                        "testGroups": testGroups
                    })

        return filegroups

    def generate_legacy_group_record(self, group):
        return "[L = " + str(int(self._outputSize)/8) + "]"

    def generate_legacy_test_case_record(self, group, test):
        if test['_testCaseSubType'] == 'Monte':
            res = "Seed = %s" % test['msg'].lower()
        else:
            msg = test['msg'].lower()
            if int(test['len']) == 0:
                msg = "00"

            res = """Len = {length}
Msg = {msg}""".format(length=test['len'], msg=msg)

        return res


    def generate_legacy_header(self, groups, py_timestamp):
        """Generate a legacy header.
        Parameter is a timestamp as a python object."""

        # Hash wants to describe whether this is bit-oriented or byte-oriented.
        # We can infer based on the lengths; if there are any odd numbers, then it
        # is bit-oriented. Otherwise, technically, we are only looking for lengths
        # which are evenly divisible by 8.

        # SHA-512/256 or SHA-1 or SHA-256
        header_alg = 'SHA-' + (self._meta['algorithm'][3:])
        mode = 'BYTE'
        # Because SHA is split in test cases instead of test groups, we process it this way
        for tc in groups[0]['tests']:
            # If odd, then bit-oriented
            if int(tc['len']) % 2:
                mode = 'BIT'
                break

        header = """#  CAVS 21.4
#  "{header_alg} {subTestType}" information for TBD
#  {header_alg} tests are configured for {mode} oriented implementations
#  Generated on {ctime}""".format(
            mode=mode, 
            header_alg=header_alg, 
            subTestType=groups[0]['tests'][0]['_testCaseSubType'], 
            ctime=time.ctime(py_timestamp)
        )
        return header



    def detect_test_sub_type(self, tg):
        if tg["testType"] == 'MCT':
            for tc in tg['tests']:
                tc['_testCaseSubType'] = 'Monte'
            return 'Monte'

        print "%s %s" % (self.algorithm, tg['tgId'])

        # For this, we need to actually subdivide the test cases themselves...
        for tc in tg["tests"]:
            if tc['len'] <= self._blockSize:
                tc['_testCaseSubType'] = 'ShortMsg'
            elif tc['len'] > self._blockSize:
                tc['_testCaseSubType'] = 'LongMsg'
            else:
                raise RuntimeError("Unknown test case sub type for test case %s in group %s" % (tc['tcId'], tg['tgId']))
            self._add_to_index('_testCaseSubType', tc)

        return tg["testType"]        # Default is to return the actual test type


if __name__ == "__main__":
    j = json.loads("\n".join(sys.stdin.readlines()))
    # To help with debugging with pdb after reading from stdin
    sys.stdin = open('/dev/tty')

    try:
        outdir = sys.argv[1]
    except IndexError:
        outdir = "."

    a = SHA(j[1]['algorithm'])
    a.json = j
    a.to_cavs(outdir)
