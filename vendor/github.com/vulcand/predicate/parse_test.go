package predicate

import (
	"fmt"
	"testing"

	"github.com/gravitational/trace"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) { check.TestingT(t) }

type PredicateSuite struct {
}

var _ = check.Suite(&PredicateSuite{})

func (s *PredicateSuite) getParser(c *check.C) Parser {
	return s.getParserWithOpts(c, nil, nil)
}

func (s *PredicateSuite) getParserWithOpts(c *check.C, getID GetIdentifierFn, getProperty GetPropertyFn) Parser {
	p, err := NewParser(Def{
		Operators: Operators{
			AND: numberAND,
			OR:  numberOR,
			GT:  numberGT,
			LT:  numberLT,
			EQ:  numberEQ,
			NEQ: numberNEQ,
			LE:  numberLE,
			GE:  numberGE,
		},
		Functions: map[string]interface{}{
			"DivisibleBy":        divisibleBy,
			"Remainder":          numberRemainder,
			"Len":                stringLength,
			"number.DivisibleBy": divisibleBy,
			"Equals":             Equals,
			"Contains":           Contains,
		},
		GetIdentifier: getID,
		GetProperty:   getProperty,
	})
	c.Assert(err, check.IsNil)
	c.Assert(p, check.NotNil)
	return p
}

func (s *PredicateSuite) TestSinglePredicate(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("DivisibleBy(2)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(2))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
}

func (s *PredicateSuite) TestModulePredicate(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("number.DivisibleBy(2)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(2))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
}

func (s *PredicateSuite) TestJoinAND(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("DivisibleBy(2) && DivisibleBy(3)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, false)
	c.Assert(fn(3), check.Equals, false)
	c.Assert(fn(6), check.Equals, true)
}

func (s *PredicateSuite) TestJoinOR(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("DivisibleBy(2) || DivisibleBy(3)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, true)
	c.Assert(fn(5), check.Equals, false)
}

func (s *PredicateSuite) TestGT(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) > 1")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, false)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
	c.Assert(fn(4), check.Equals, false)
	c.Assert(fn(5), check.Equals, true)
}

func (s *PredicateSuite) TestGTE(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) >= 1")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, true)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
	c.Assert(fn(4), check.Equals, true)
	c.Assert(fn(5), check.Equals, true)
}

func (s *PredicateSuite) TestLT(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) < 2")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, true)
	c.Assert(fn(2), check.Equals, false)
	c.Assert(fn(3), check.Equals, true)
	c.Assert(fn(4), check.Equals, true)
	c.Assert(fn(5), check.Equals, false)
}

func (s *PredicateSuite) TestLE(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) <= 2")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, true)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, true)
	c.Assert(fn(4), check.Equals, true)
	c.Assert(fn(5), check.Equals, true)
}

func (s *PredicateSuite) TestEQ(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) == 2")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, false)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
	c.Assert(fn(4), check.Equals, false)
	c.Assert(fn(5), check.Equals, true)
}

func (s *PredicateSuite) TestNEQ(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) != 2")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, true)
	c.Assert(fn(2), check.Equals, false)
	c.Assert(fn(3), check.Equals, true)
	c.Assert(fn(4), check.Equals, true)
	c.Assert(fn(5), check.Equals, false)
}

func (s *PredicateSuite) TestParen(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("(Remainder(3) != 1) && (Remainder(3) != 0)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(0), check.Equals, false)
	c.Assert(fn(1), check.Equals, false)
	c.Assert(fn(2), check.Equals, true)
}

func (s *PredicateSuite) TestStrings(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse(`Remainder(3) == Len("hi")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(0), check.Equals, false)
	c.Assert(fn(1), check.Equals, false)
	c.Assert(fn(2), check.Equals, true)
}

func (s *PredicateSuite) TestGTFloat64(c *check.C) {
	p := s.getParser(c)

	pr, err := p.Parse("Remainder(3) > 1.2")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(1))
	fn := pr.(numberPredicate)
	c.Assert(fn(1), check.Equals, false)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
	c.Assert(fn(4), check.Equals, false)
	c.Assert(fn(5), check.Equals, true)
}

func (s *PredicateSuite) TestIdentifier(c *check.C) {
	getID := func(fields []string) (interface{}, error) {
		c.Assert(fields, check.DeepEquals, []string{"first", "second", "third"})
		return 2, nil
	}
	p := s.getParserWithOpts(c, getID, nil)

	pr, err := p.Parse("DivisibleBy(first.second.third)")
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(2))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
}

func (s *PredicateSuite) TestMap(c *check.C) {
	getID := func(fields []string) (interface{}, error) {
		c.Assert(fields, check.DeepEquals, []string{"first", "second"})
		return map[string]int{"key": 2}, nil
	}
	getProperty := func(mapVal, keyVal interface{}) (interface{}, error) {
		m := mapVal.(map[string]int)
		k := keyVal.(string)
		return m[k], nil
	}

	p := s.getParserWithOpts(c, getID, getProperty)

	pr, err := p.Parse(`DivisibleBy(first.second["key"])`)
	c.Assert(err, check.IsNil)
	c.Assert(pr, check.FitsTypeOf, divisibleBy(2))
	fn := pr.(numberPredicate)
	c.Assert(fn(2), check.Equals, true)
	c.Assert(fn(3), check.Equals, false)
}

func (s *PredicateSuite) TestIdentifierAndFunction(c *check.C) {
	getID := func(fields []string) (interface{}, error) {
		switch fields[0] {
		case "firstSlice":
			return []string{"a"}, nil
		case "secondSlice":
			return []string{"b"}, nil
		case "a":
			return "a", nil
		case "b":
			return "b", nil
		}
		return nil, nil
	}
	p := s.getParserWithOpts(c, getID, nil)

	pr, err := p.Parse("Equals(firstSlice, firstSlice)")
	c.Assert(err, check.IsNil)
	fn := pr.(BoolPredicate)
	c.Assert(fn(), check.Equals, true)

	pr, err = p.Parse("Equals(a, a)")
	c.Assert(err, check.IsNil)
	fn = pr.(BoolPredicate)
	c.Assert(fn(), check.Equals, true)

	pr, err = p.Parse("Equals(firstSlice, secondSlice)")
	c.Assert(err, check.IsNil)
	fn = pr.(BoolPredicate)
	c.Assert(fn(), check.Equals, false)
}

func (s *PredicateSuite) TestContains(c *check.C) {
	val := TestStruct{}
	val.Param.Key1 = map[string][]string{"key": []string{"a", "b", "c"}}

	getID := func(fields []string) (interface{}, error) {
		return GetFieldByTag(val, "json", fields[1:])
	}
	p := s.getParserWithOpts(c, getID, GetStringMapValue)

	pr, err := p.Parse(`Contains(val.param.key1["key"], "a")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, true)

	pr, err = p.Parse(`Contains(val.param.key1["key"], "z")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, false)

	pr, err = p.Parse(`Contains(val.param.key1["missing"], "a")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, false)
}

func (s *PredicateSuite) TestEquals(c *check.C) {
	val := TestStruct{}
	val.Param.Key2 = map[string]string{"key": "a"}

	getID := func(fields []string) (interface{}, error) {
		return GetFieldByTag(val, "json", fields[1:])
	}
	p := s.getParserWithOpts(c, getID, GetStringMapValue)

	pr, err := p.Parse(`Equals(val.param.key2["key"], "a")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, true)

	pr, err = p.Parse(`Equals(val.param.key2["key"], "b")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, false)

	pr, err = p.Parse(`Contains(val.param.key2["missing"], "z")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, false)

	pr, err = p.Parse(`Contains(val.param.key1["missing"], "z")`)
	c.Assert(err, check.IsNil)
	c.Assert(pr.(BoolPredicate)(), check.Equals, false)
}

// TestStruct is a test sturcture with json tags
type TestStruct struct {
	Param struct {
		Key1 map[string][]string `json:"key1,omitempty"`
		Key2 map[string]string   `json:"key2,omitempty"`
	} `json:"param,omitempty"`
}

func (s *PredicateSuite) TestGetTagField(c *check.C) {
	val := TestStruct{}
	val.Param.Key1 = map[string][]string{"key": []string{"val"}}

	type testCase struct {
		tag    string
		fields []string
		val    interface{}
		expect interface{}
		err    error
	}
	testCases := []testCase{
		// nested field
		{tag: "json", val: val, fields: []string{"param", "key1"}, expect: val.Param.Key1},
		// pointer to struct
		{tag: "json", val: &val, fields: []string{"param", "key1"}, expect: val.Param.Key1},
		// not found field
		{tag: "json", val: &val, fields: []string{"param", "key3"}, err: trace.NotFound("not found")},
		// nil pointer
		{tag: "json", val: nil, fields: []string{"param", "key1"}, err: trace.BadParameter("bad param")},
	}

	for i, tc := range testCases {
		comment := check.Commentf("test case %v", i)
		out, err := GetFieldByTag(tc.val, tc.tag, tc.fields)
		if tc.err != nil {
			c.Assert(err, check.FitsTypeOf, tc.err, comment)
		} else {
			c.Assert(err, check.IsNil, comment)
			c.Assert(out, check.DeepEquals, tc.expect, comment)
		}
	}
}

func (s *PredicateSuite) TestUnhappyCases(c *check.C) {
	cases := []string{
		")(",                      // invalid expression
		"SomeFunc",                // unsupported id
		"Remainder(banana)",       // unsupported argument
		"Remainder(1, 2)",         // unsupported arguments count
		"Remainder(Len)",          // unsupported argument
		`Remainder(Len("Ho"))`,    // unsupported argument
		"Bla(1)",                  // unknown method call
		"0.2 && Remainder(1)",     // unsupported value
		`Len("Ho") && 0.2`,        // unsupported value
		"func(){}()",              // function call
		"Remainder(3) >> 3",       // unsupported operator
		`Remainder(3) > "banana"`, // unsupported comparison type
	}
	p := s.getParser(c)
	for _, expr := range cases {
		pr, err := p.Parse(expr)
		c.Assert(err, check.NotNil)
		c.Assert(pr, check.IsNil)
	}
}

type numberPredicate func(v int) bool
type numberMapper func(v int) int

func divisibleBy(divisor int) numberPredicate {
	return func(v int) bool {
		return v%divisor == 0
	}
}

func numberAND(a, b numberPredicate) numberPredicate {
	return func(v int) bool {
		return a(v) && b(v)
	}
}

func numberOR(a, b numberPredicate) numberPredicate {
	return func(v int) bool {
		return a(v) || b(v)
	}
}

func numberRemainder(divideBy int) numberMapper {
	return func(v int) int {
		return v % divideBy
	}
}

func numberGT(m numberMapper, value interface{}) (numberPredicate, error) {
	switch value.(type) {
	case int:
	case float64:
	default:
		return nil, fmt.Errorf("GT: unsupported argument type: %T", value)
	}
	return func(v int) bool {
		switch val := value.(type) {
		case int:
			return m(v) > val
		case float64:
			return m(v) > int(val)
		default:
			return true
		}
	}, nil
}

func numberGE(m numberMapper, value int) (numberPredicate, error) {
	return func(v int) bool {
		return m(v) >= value
	}, nil
}

func numberLE(m numberMapper, value int) (numberPredicate, error) {
	return func(v int) bool {
		return m(v) <= value
	}, nil
}

func numberLT(m numberMapper, value int) numberPredicate {
	return func(v int) bool {
		return m(v) < value
	}
}

func numberEQ(m numberMapper, value int) numberPredicate {
	return func(v int) bool {
		return m(v) == value
	}
}

func numberNEQ(m numberMapper, value int) numberPredicate {
	return func(v int) bool {
		return m(v) != value
	}
}

func stringLength(v string) int {
	return len(v)
}
