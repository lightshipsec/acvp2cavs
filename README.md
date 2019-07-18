# Convert ACVP Test Vectors to CAVS Format

ACVP test vectors are JSON-based and conform with the ACVP standard.
CAVS is the legacy format and are structured-text format.

Whereas ACVP vectors have a relatively uniform structure with a documented set of key/value pairs, CAVS has several oddities in their structure which makes conversion between the two somewhat non-trivial.  Couple with the fact that some algorithms in ACVP are not represented in CAVS means that a converter tool will only be useful for a short window of opportunity while ACVP gets running.

From what I have been able to tell, the primary challenge between converting from ACVP to CAVS is how tests and test groups are further grouped (or regrouped) between ACVP and CAVS.  Furthermore, this is compounded by the fact that in CAVS, test files have specific names corresponding to certain tests which may be significant to some test harnesses.  As an example, AES splits certain test cases in 6 files corresponding to GFSbox, KeySbox, VarTxt, VarKey, MMT and monte-carlo testing.  However, in ACVP, the vectors are only split into two distinct groups (functional testing and monte carlo).  Another example is in HMAC testing in which all HMAC test vectors are contained in a single file for CAVS, but are split into individual test vector sets for ACVP.

The ACVP to CAVS converter considers the following:
  - CAVS file names may be significant to a vendor's test harness and we want to replicate it as much as we can
  - CAVS header information in the comment field may be significant and we want to replicate it as much as we can
  - CAVS intra-file groups are denoted by significant information between square brackets [L=20 SHAAlg=SHA\_2]
  - CAVS test cases may be split into *more* files than its associated ACVP vector set
  - CAVS test cases may be constructed by combining more than one ACVP vector set
  - ACVP may introduce new test cases which may not be able to be fully represented
  - ACVP may remove or introduce explicit details about a test group or test case; CAVS may have to synthesize the missing information or drop information entirely.


The initial version of the ACVP to CAVS converter was highly experimental in nature and this shows in how the code is structured and used.  The code should be cleaned up as the design matures.
