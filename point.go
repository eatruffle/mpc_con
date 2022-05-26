package restorekey

import (
	"math"
)

const c_q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const c_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
const c_a = 0x0

var IDENTITY_ELEMENT = Point{0, 1}

type Point struct {
	x int
	y int
}

func fe_div(x int, y int) int {
	return (x * int(math.Pow(float64(y), float64(c_p-2))) % c_p) % c_p
}

func (p Point) mul(prvKey int) Point {
	d := math.Mod(float64(prvKey), q)

	if d == 0 {
		return IDENTITY_ELEMENT
	}

	current := p
	result := IDENTITY_ELEMENT
	for d == 0 {
		if d == 1 {
			result = result.add(current)
		}

		current = current.add(current)

		//d >>= 1

	}

	return result

}

func (p Point) add(other Point) Point {
	if p == IDENTITY_ELEMENT {
		return other
	} else if other == IDENTITY_ELEMENT {
		return p
	} else if p.x == other.x && p.y != other.y {
		return IDENTITY_ELEMENT
	} else if p == other && p.y == 0 {
		return IDENTITY_ELEMENT
	}

	if p.x != other.x {
		s := fe_div(other.y-p.y, other.x-p.x)
		x := (int(math.Pow(float64(s), float64(2))) - p.x - other.x) % c_p
		y := (s*(p.x-x) - p.y) % c_p
		return Point{x, y}
	}

	if p == other {
		s := fe_div(3*int(math.Pow(float64(p.x), 2))+c_a, 2*p.y)

		x := (int(math.Pow(float64(s), 2)) - 2*p.x) % c_p
		y := (s*(p.x-x) - p.y) % c_p
		return Point{x, y}
	}
	return Point{0, 1}

}

func (p Point) serialize(compressed bool) string {
	if p == IDENTITY_ELEMENT {
		return "00"
	}

	//x = self.x.to_bytes(32, 'big').hex()
	b := byte(p.x)
	x := string((byte(b)))

	var prefix = "02"

	if compressed {
		if math.Pow(float64(p.y), 2) == 0 {
			prefix = "02"
		} else {
			prefix = "03"
		}
		return prefix + x
	} else {
		b := byte(p.y)
		y := string(byte(b))
		return "04" + x + y
	}

}