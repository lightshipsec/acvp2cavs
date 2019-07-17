import json
import sys
import time
from pdb import set_trace as bp
from cavsalg import CAVSAlgorithm


class HMAC(CAVSAlgorithm):
    def __init__(self, alg):
        if not alg.startswith('HMAC-SHA'):
            raise RuntimeError("Algorithm %s is not a recognized keyed-hash algorithm." % alg)

        super(HMAC, self).__init__(alg)

        if 'SHA-1' in alg.upper():
            self._outputSize = 160
        else:
            # We only want the END number as the output size (last 3 digits)
            self._outputSize = int(alg[-3:])

        if 'SHA-1' in alg.upper():
            self._underlyingHash = 'SHA-1'
        elif 'SHA2' in alg.upper():
            self._underlyingHash = 'SHA-2'
        elif 'SHA3' in alg.upper():
            self._underlyingHash = 'SHA-3'
        else:
            raise RuntimeError("Algorithm %s is not a recognized underlying hash algorithm." % alg)


    def legacy_file_groups(self):
        """Legacy file groups are HMAC.req
        Grouping is output size (known), and base algorithm (known)
        Return a list of the filenames along with the grouping criteria needed to generate them.
        """
        filegroups = []
        # There is literally only one group in this file that I am aware of. The groupings are made up
        # of the size of the underlying hash and the underlying algorithm prefix (which is dumb).
        filegroups.append({
            "filename": 'HMAC.req',
            "testGroups": self.testGroups
        })
        return filegroups

    def generate_legacy_group_record(self, group):
        if 'SHA-1' in self.algorithm:
            algStr = "SHA_1"
        elif 'SHA2' in self.algorithm:
            algStr = "SHA_2"
        elif 'SHA3' in self.algorithm:
            algStr = 'SHA_3'        # Untested!
        else:
            raise RuntimeError("Unknown underlying hash algorithm %s in HMAC" % self.algorithm)

        return "[L=%s SHAAlg=%s]" % (
            int(group['macLen'])/8,
            algStr
        )

    def generate_legacy_test_case_record(self, group, test):
        count = int(test['tcId']) - int(group['tests'][0]['tcId'])
        klen = int(group['keyLen'])
        tlen = int(group['macLen'])      # Truncated length?
        key = test['key'].lower()
        msg = test['msg'].lower()

        res = """Count = {count}
Klen = {klen}
Tlen = {tlen}
Key = {key}
Msg = {msg}""".format(count=count, klen=klen/8, tlen=tlen/8, key=key, msg=msg)

        return res


    def generate_legacy_header(self, groups, py_timestamp):
        """Generate a legacy header.
        Parameter is a timestamp as a python object."""

        # Hmmm, ACVP only has one algorithm per vector set. Unlike CAVS which bundles them.
        tested = "{outsize} with  {algStr}".format(outsize=int(self._outputSize)/8, algStr=self._underlyingHash)

        header = """#  CAVS 21.4
#  HMAC information for TBD
#  Hash sizes/Hash algorithms tested: {tested}
#  Generated on {ctime}""".format(
            tested=tested,
            ctime=time.ctime(py_timestamp)
        )
        return header



    def detect_test_sub_type(self, tg):
        return tg["testType"]        # Default is to return the actual test type


if __name__ == "__main__":
    j = json.loads("\n".join(sys.stdin.readlines()))
    # To help with debugging with pdb after reading from stdin
    sys.stdin = open('/dev/tty')

    try:
        outdir = sys.argv[1]
    except IndexError:
        outdir = "."

    a = HMAC(j[1]['algorithm'])
    a.json = j
    a.to_cavs(outdir)
