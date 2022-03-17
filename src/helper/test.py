from ..helper import helper
from . import helper

eccTests = {
    "HelperTest": [
        "test_little_endian_to_int",
        "test_int_to_little_endian"
    ]
}

for testTarget, testcases in eccTests.items():
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n")
    print("Start Test: " + testTarget)
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n\n")
    for testcase in testcases:
        print("😄" + testcase)
        helper.run(getattr(helper, testTarget)(testcase))
