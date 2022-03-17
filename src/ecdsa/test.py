from ..helper import helper
from . import ecc
from . import s256Ecc

eccTests = {
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
    ],
    "ECCTest": [
        "test_on_curve",
        "test_add",
        "test_rmul"
    ]
}

for testTarget, testcases in eccTests.items():
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n")
    print("Start Test: " + testTarget)
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n\n")
    for testcase in testcases:
        print("😄" + testcase)
        helper.run(getattr(ecc, testTarget)(testcase))

s256EccTests = {
    "S256Test": [
        "test_order",
        "test_pubpoint",
        "test_verify",
        "test_sec",
        "test_address"
    ],
    "SignatureTest": [
        "test_der"
    ],
    "PrivateKeyTest": [
        "test_sign",
        "test_wif"
    ]
}


for testTarget, testcases in s256EccTests.items():
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n")
    print("Start Test: " + testTarget)
    print("\n🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓🤓\n\n")
    for testcase in testcases:
        print("😄" + testcase)
        helper.run(getattr(s256Ecc, testTarget)(testcase))
