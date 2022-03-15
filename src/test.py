
import helper
import ecc


tests = {
    "FieldElementTest": [
        "test_ne",
        "test_add",
        "test_sub",
        "test_pow",
        "test_div",
    ],
    "PointTest": [
        "test_ne",
        "test_add0",
        "test_add1",
        "test_add2"
    ]
}

for testTarget, testcases in tests.items():
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n")
    print("Start Test: " + testTarget)
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n\n")
    for testcase in testcases:
        print("😄" + testcase)
        helper.run(getattr(ecc, testTarget)(testcase))
