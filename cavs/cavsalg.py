import time
import json
import sys
import os

from pdb import set_trace as bp


class DottedDict(dict):
    def __getattr__(self, k):
        return super(DottedDict, self).__getitem__(k)
    def __setattr__(self, k, v):
        return super(DottedDict, self).__setitem__(k, v)


class CAVSAlgorithm(object):
    def __init__(self, algorithm):
        self._json = None
        self._meta = {"algorithm":algorithm}
        self.legacy = DottedDict()
        self._vectors = None
        self._header = None
        self._indexes = {}

    def __getattr__(self, k):
        if k in self._vectors:
            return self._vectors[k]
        else:
            raise AttributeError("JSON does not have key %s" % k)

    def findAll(self, tg_list, criteria_dict):
        """Query the test group list for various properties.
        The criteria dictionary has a few properties.
        1) If keyname is prefixed by '!' then inverts simple comparison.
        2) If value is a callable, then call the function and pass the TG key value field (boolean is expected output).
        """
        invert = False
        res = []
        for tg in tg_list:
            if criteria_dict is None:
                res.append(tg)
                continue

            match = 0

            for k,v in criteria_dict.iteritems():
                if k.startswith("!"):
                    k = k[1:]
                    invert = True
                try:
                    if callable(v):
                        if v(tg[k]) == (not invert):
                            match += 1
                    else:
                        if v == tg[k] and (not invert):
                            match += 1
                except Exception as ex:
                    print >> sys.stderr, ex
                    continue

            # All criteria have to match
            if match == len(criteria_dict.keys()):
                res.append(tg)
        return res

    @property
    def json(self):
        return self._json

    @json.setter
    def json(self, json):
        self._json = json
        self._vectors = json[1]
        self._headers = json[0]
        return self._json

    def from_acvp(self, json_str):
        self.json = json.loads(json_str)

    def _add_to_index(self, index, tg):
        if index not in self._indexes:
            self._indexes[index] = {}
        if tg[index] not in self._indexes[index]:
            self._indexes[index][tg[index]] = []
        self._indexes[index][tg[index]].append(tg)


    def legacy_preprocess(self):
        """Tag the existing ACV tree with decorators that we can use for traversal
        when dealing with the legacy output format.
        """
        for tg in self.testGroups:
            tg['_testSubType'] = self.detect_test_sub_type(tg)
            self._add_to_index('testType', tg)
            self._add_to_index('_testSubType', tg)

    def detect_test_sub_type(self, tg):
        pass

    def legacy_group_by(self):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def legacy_file_groups(self):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def generate_legacy_header(self, timestamp):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def legacy_test_groups(self, timestamp):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def generate_legacy_group_record(self):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def legacy_test_cases(self, test_group):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def generate_legacy_test_case_record(self, test_case):
        raise NotImplementedError("Not implemented in %s" % self.__class__.__name__)

    def to_cavs(self, out_dir):
        # This bit will introduce meta data to help re-split the test data like old legacy
        self.legacy_preprocess()

        for file_groups in self.legacy_file_groups():
            with open(os.path.join(out_dir, file_groups["filename"]), "wt") as output:
                print >> output, self.generate_legacy_header(file_groups["testGroups"], time.time())

                for test_group in file_groups["testGroups"]:
                    print >> output, ""
                    print >> output, self.generate_legacy_group_record(test_group)

                    for test_case in test_group["tests"]:
                        print >> output, ""
                        print >> output, self.generate_legacy_test_case_record(test_group, test_case)



