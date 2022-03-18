from typing import Union


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
