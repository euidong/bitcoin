
import helper
import ecc


tests = [
    "test_ne",
    "test_add",
    "test_sub",
    "test_pow",
    "test_div"
]


for test in tests:
    print("😄😄😄" + test + "😄😄😄")
    helper.run(ecc.FieldElementTest(test))
