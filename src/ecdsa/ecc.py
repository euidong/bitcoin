from typing import Union
from unittest import TestCase


class FieldElement:
    def __init__(self, num: int, prime: int):
        if num >= prime or num < 0:
            err = 'Num {} not in field range 0 to {}'.format(num, prime - 1)
            raise ValueError(err)
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __eq__(self, other: 'FieldElement') -> bool:
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other: 'FieldElement') -> bool:
        if other is None:
            return False
        return self.num != other.num or self.prime != other.prime

    def __add__(self, other: 'FieldElement') -> 'FieldElement':
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other: 'FieldElement') -> 'FieldElement':
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other: 'FieldElement') -> 'FieldElement':
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = self.num * other.num % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent: int) -> 'FieldElement':
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other: 'FieldElement') -> 'FieldElement':
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        other_inv = pow(other, other.prime - 2)
        num = self.num * other_inv.num % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient: int) -> 'FieldElement':
        num = self.num * coefficient % self.prime
        return self.__class__(num, self.prime)


class FieldElementTest(TestCase):
    def test_ne(self):
        a = FieldElement(2, 31)
        b = FieldElement(2, 31)
        c = FieldElement(15, 31)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FieldElement(2, 31)
        b = FieldElement(15, 31)
        self.assertEqual(a + b, FieldElement(17, 31))
        a = FieldElement(17, 31)
        b = FieldElement(21, 31)
        self.assertEqual(a + b, FieldElement(7, 31))

    def test_sub(self):
        a = FieldElement(29, 31)
        b = FieldElement(4, 31)
        self.assertEqual(a - b, FieldElement(25, 31))
        a = FieldElement(15, 31)
        b = FieldElement(30, 31)
        self.assertEqual(a - b, FieldElement(16, 31))

    def test_mul(self):
        a = FieldElement(24, 31)
        b = FieldElement(19, 31)
        self.assertEqual(a * b, FieldElement(22, 31))

    def test_pow(self):
        a = FieldElement(17, 31)
        self.assertEqual(a**3, FieldElement(15, 31))
        a = FieldElement(5, 31)
        b = FieldElement(18, 31)
        self.assertEqual(a**5 * b, FieldElement(16, 31))

    def test_div(self):
        a = FieldElement(3, 31)
        b = FieldElement(24, 31)
        self.assertEqual(a / b, FieldElement(4, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a**-3, FieldElement(29, 31))
        a = FieldElement(4, 31)
        b = FieldElement(11, 31)
        self.assertEqual(a**-4 * b, FieldElement(13, 31))


class Point:
    def __init__(self, x: Union['FieldElement', int], y: Union['FieldElement', int], a: int, b: int):
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        if self.x is None and self.x is None:
            return
        if self.y ** 2 != self.x ** 3 + a * x + b:
            raise ValueError('({} {}) is not on the curve'.format(x, y))

    def __repr__(self) -> str:
        if self.x is None:
            return 'Point(Infinity)'
        else:
            return 'Point({}, {})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other: 'Point') -> bool:
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b
        # return not (self != other)

    def __ne__(self, other: 'Point') -> bool:
        return not (self == other)
        # return self.x != other.x or self.y != other.y \
        #     or self.a != other.a or self.b != other.b

    def __add__(self, other: 'Point') -> 'Point':
        if self.a != other.a or self.b != other.b:
            raise TypeError('Cannot add two points in different Curves')
        if self.x == None:
            return self.__class__(other.x, other.y, other.a, other.b)
        if other.x == None:
            return self.__class__(self.x, self.y, self.a, self.b)
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        s: int
        if self.x == other.x and self.y == other.y:
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
        else:
            s = (other.y - self.y) / (other.x - self.x)
        x3 = s ** 2 - self.x - other.x
        y3 = s * (self.x - x3) - self.y
        return self.__class__(x3, y3, self.a, self.b)

    # * (for __rmul__)
    # * It's very intuitive implementation.
    # def __rmul__(self, coefficient: int) -> 'Point':
    #     result = self.__class__(None, None, self.a, self.b)
    #     for _ in range(0, coefficient):
    #         result += self
    #     return result

    # * (for __rmul__)
    # * If you wanna get More Good Performance, use Bellow
    def __rmul__(self, coefficient: int) -> 'Point':
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)

        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


class PointTest(TestCase):
    def test_ne(self):
        a = Point(x=3, y=-7, a=5, b=7)
        b = Point(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_add0(self):
        a = Point(x=None, y=None, a=5, b=7)
        b = Point(x=2, y=5, a=5, b=7)
        c = Point(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = Point(x=3, y=7, a=5, b=7)
        b = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + a, Point(x=18, y=77, a=5, b=7))


class ECCTest(TestCase):
    def test_on_curve(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x_raw, y_raw in valid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            Point(x, y, a, b)
        for x_raw, y_raw in invalid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)

    def test_add(self):
        # tests the following additions on curve y^2=x^3-7 over F_223:
        # (192,105) + (17,56)
        # (47,71) + (117,141)
        # (143,98) + (76,66)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        additions = (
            # (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        )

        for x1_row, y1_row, x2_row, y2_row, x3_row, y3_row in additions:
            x1 = FieldElement(x1_row, prime)
            y1 = FieldElement(y1_row, prime)
            p = Point(x1, y1, a, b)

            x2 = FieldElement(x2_row, prime)
            y2 = FieldElement(y2_row, prime)
            q = Point(x2, y2, a, b)

            x3 = FieldElement(x3_row, prime)
            y3 = FieldElement(y3_row, prime)
            r = Point(x3, y3, a, b)

            self.assertEqual(p + q, r)

    def test_rmul(self):
        # tests the following scalar multiplications
        # 2*(192,105)
        # 2*(143,98)
        # 2*(47,71)
        # 4*(47,71)
        # 8*(47,71)
        # 21*(47,71)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        multiplications = (
            # (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
            (21, 47, 71, None, None),
        )

        # iterate over the multiplications
        for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = Point(x1, y1, a, b)
            # initialize the second point based on whether it's the point at infinity
            if x2_raw is None:
                p2 = Point(None, None, a, b)
            else:
                x2 = FieldElement(x2_raw, prime)
                y2 = FieldElement(y2_raw, prime)
                p2 = Point(x2, y2, a, b)

            # check that the product is equal to the expected point
            self.assertEqual(s * p1, p2)
