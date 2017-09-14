/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package candiedyaml

import (
	"math"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resolver", func() {
	var event yaml_event_t

	var nulls = []string{"~", "null", "Null", "NULL"}

	BeforeEach(func() {
		event = yaml_event_t{}
	})

	Context("Resolve", func() {
		Context("Implicit events", func() {
			checkNulls := func(f func()) {
				for _, null := range nulls {
					event = yaml_event_t{implicit: true}
					event.value = []byte(null)
					f()
				}
			}

			BeforeEach(func() {
				event.implicit = true
			})

			Context("String", func() {
				It("resolves a string", func() {
					aString := ""
					v := reflect.ValueOf(&aString)
					event.value = []byte("abc")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_STR_TAG))
					Expect(aString).To(Equal("abc"))
				})

				It("resolves the empty string", func() {
					aString := "abc"
					v := reflect.ValueOf(&aString)
					event.value = []byte("")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_STR_TAG))
					Expect(aString).To(Equal(""))

				})

				It("resolves null", func() {
					checkNulls(func() {
						aString := "abc"
						v := reflect.ValueOf(&aString)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(aString).To(Equal(""))
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						aString := "abc"
						pString := &aString
						v := reflect.ValueOf(&pString)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pString).To(BeNil())
					})
				})

			})

			Context("Booleans", func() {
				match_bool := func(val string, expected bool) {
					b := !expected

					v := reflect.ValueOf(&b)
					event.value = []byte(val)

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_BOOL_TAG))
					Expect(b).To(Equal(expected))
				}

				It("resolves on", func() {
					match_bool("on", true)
					match_bool("ON", true)
				})

				It("resolves off", func() {
					match_bool("off", false)
					match_bool("OFF", false)
				})

				It("resolves true", func() {
					match_bool("true", true)
					match_bool("TRUE", true)
				})

				It("resolves false", func() {
					match_bool("false", false)
					match_bool("FALSE", false)
				})

				It("resolves yes", func() {
					match_bool("yes", true)
					match_bool("YES", true)
				})

				It("resolves no", func() {
					match_bool("no", false)
					match_bool("NO", false)
				})

				It("reports an error otherwise", func() {
					b := true
					v := reflect.ValueOf(&b)
					event.value = []byte("fail")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid boolean: 'fail' at line 0, column 0"))
				})

				It("resolves null", func() {
					checkNulls(func() {
						b := true
						v := reflect.ValueOf(&b)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(b).To(BeFalse())
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						b := true
						pb := &b
						v := reflect.ValueOf(&pb)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pb).To(BeNil())
					})
				})
			})

			Context("Ints", func() {
				It("simple ints", func() {
					i := 0
					v := reflect.ValueOf(&i)
					event.value = []byte("1234")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(1234))
				})

				It("positive ints", func() {
					i := int16(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("+678")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(int16(678)))
				})

				It("negative ints", func() {
					i := int32(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("-2345")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(int32(-2345)))
				})

				It("base 8", func() {
					i := 0
					v := reflect.ValueOf(&i)
					event.value = []byte("0o12")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(10))
				})

				It("base 16", func() {
					i := 0
					v := reflect.ValueOf(&i)
					event.value = []byte("0xff")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(255))
				})

				It("fails on overflow", func() {
					i := int8(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("2345")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid integer: '2345' at line 0, column 0"))
				})

				It("fails on invalid int", func() {
					i := 0
					v := reflect.ValueOf(&i)
					event.value = []byte("234f")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid integer: '234f' at line 0, column 0"))
				})

				It("resolves null", func() {
					checkNulls(func() {
						i := 1
						v := reflect.ValueOf(&i)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(i).To(Equal(0))
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						i := 1
						pi := &i
						v := reflect.ValueOf(&pi)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pi).To(BeNil())
					})
				})

				It("returns a Number", func() {
					var i Number
					v := reflect.ValueOf(&i)

					tag, err := resolve_int("12345", v.Elem(), true, event)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(Number("12345")))
					Expect(i.Int64()).To(Equal(int64(12345)))

					event.value = []byte("1234")
					tag, err = resolve(event, v.Elem(), true)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(Number("1234")))
				})
			})

			Context("UInts", func() {
				It("resolves simple uints", func() {
					i := uint(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("1234")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(uint(1234)))
				})

				It("resolves positive uints", func() {
					i := uint16(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("+678")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(uint16(678)))
				})

				It("base 8", func() {
					i := uint(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("0o12")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(uint(10)))
				})

				It("base 16", func() {
					i := uint(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("0xff")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(uint(255)))
				})

				It("fails with negative ints", func() {
					i := uint(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("-2345")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Unsigned int with negative value: '-2345' at line 0, column 0"))
				})

				It("fails on overflow", func() {
					i := uint8(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("2345")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid unsigned integer: '2345' at line 0, column 0"))
				})

				It("resolves null", func() {
					checkNulls(func() {
						i := uint(1)
						v := reflect.ValueOf(&i)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(i).To(Equal(uint(0)))
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						i := uint(1)
						pi := &i
						v := reflect.ValueOf(&pi)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pi).To(BeNil())
					})
				})

				It("returns a Number", func() {
					var i Number
					v := reflect.ValueOf(&i)

					tag, err := resolve_uint("12345", v.Elem(), true, event)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(Number("12345")))

					event.value = []byte("1234")
					tag, err = resolve(event, v.Elem(), true)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_INT_TAG))
					Expect(i).To(Equal(Number("1234")))
				})
			})

			Context("Floats", func() {
				It("float32", func() {
					f := float32(0)
					v := reflect.ValueOf(&f)
					event.value = []byte("2345.01")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(f).To(Equal(float32(2345.01)))
				})

				It("float64", func() {
					f := float64(0)
					v := reflect.ValueOf(&f)
					event.value = []byte("-456456.01")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(f).To(Equal(float64(-456456.01)))
				})

				It("+inf", func() {
					f := float64(0)
					v := reflect.ValueOf(&f)
					event.value = []byte("+.inf")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(f).To(Equal(math.Inf(1)))
				})

				It("-inf", func() {
					f := float32(0)
					v := reflect.ValueOf(&f)
					event.value = []byte("-.inf")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(f).To(Equal(float32(math.Inf(-1))))
				})

				It("nan", func() {
					f := float64(0)
					v := reflect.ValueOf(&f)
					event.value = []byte(".NaN")

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(math.IsNaN(f)).To(BeTrue())
				})

				It("fails on overflow", func() {
					i := float32(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("123e10000")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid float: '123e10000' at line 0, column 0"))
				})

				It("fails on invalid float", func() {
					i := float32(0)
					v := reflect.ValueOf(&i)
					event.value = []byte("123e1a")

					_, err := resolve(event, v.Elem(), false)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("Invalid float: '123e1a' at line 0, column 0"))
				})

				It("resolves null", func() {
					checkNulls(func() {
						f := float64(1)
						v := reflect.ValueOf(&f)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(f).To(Equal(0.0))
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						f := float64(1)
						pf := &f
						v := reflect.ValueOf(&pf)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pf).To(BeNil())
					})
				})

				It("returns a Number", func() {
					var i Number
					v := reflect.ValueOf(&i)

					tag, err := resolve_float("12.345", v.Elem(), true, event)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(i).To(Equal(Number("12.345")))
					Expect(i.Float64()).To(Equal(12.345))

					event.value = []byte("1.234")
					tag, err = resolve(event, v.Elem(), true)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(yaml_FLOAT_TAG))
					Expect(i).To(Equal(Number("1.234")))
				})
			})

			Context("Timestamps", func() {
				parse_date := func(val string, date time.Time) {
					d := time.Now()
					v := reflect.ValueOf(&d)
					event.value = []byte(val)

					tag, err := resolve(event, v.Elem(), false)
					Expect(err).NotTo(HaveOccurred())
					Expect(tag).To(Equal(""))
					Expect(d).To(Equal(date))
				}

				It("date", func() {
					parse_date("2002-12-14", time.Date(2002, time.December, 14, 0, 0, 0, 0, time.UTC))
				})

				It("canonical", func() {
					parse_date("2001-12-15T02:59:43.1Z", time.Date(2001, time.December, 15, 2, 59, 43, int(1*time.Millisecond), time.UTC))
				})

				It("iso8601", func() {
					parse_date("2001-12-14t21:59:43.10-05:00", time.Date(2001, time.December, 14, 21, 59, 43, int(10*time.Millisecond), time.FixedZone("", -5*3600)))
				})

				It("space separated", func() {
					parse_date("2001-12-14 21:59:43.10 -5", time.Date(2001, time.December, 14, 21, 59, 43, int(10*time.Millisecond), time.FixedZone("", -5*3600)))
				})

				It("no time zone", func() {
					parse_date("2001-12-15 2:59:43.10", time.Date(2001, time.December, 15, 2, 59, 43, int(10*time.Millisecond), time.UTC))
				})

				It("resolves null", func() {
					checkNulls(func() {
						d := time.Now()
						v := reflect.ValueOf(&d)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(d).To(Equal(time.Time{}))
					})
				})

				It("resolves null pointers", func() {
					checkNulls(func() {
						d := time.Now()
						pd := &d
						v := reflect.ValueOf(&pd)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_NULL_TAG))
						Expect(pd).To(BeNil())
					})
				})
			})

			Context("Binary tag", func() {
				It("string", func() {
					checkNulls(func() {
						event.value = []byte("YWJjZGVmZw==")
						event.tag = []byte("!binary")
						aString := ""
						v := reflect.ValueOf(&aString)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_STR_TAG))
						Expect(aString).To(Equal("abcdefg"))
					})
				})

				It("[]byte", func() {
					checkNulls(func() {
						event.value = []byte("YWJjZGVmZw==")
						event.tag = []byte("!binary")
						bytes := []byte(nil)
						v := reflect.ValueOf(&bytes)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_STR_TAG))
						Expect(bytes).To(Equal([]byte("abcdefg")))
					})
				})

				It("returns a []byte when provided no hints", func() {
					checkNulls(func() {
						event.value = []byte("YWJjZGVmZw==")
						event.tag = []byte("!binary")
						var intf interface{}
						v := reflect.ValueOf(&intf)

						tag, err := resolve(event, v.Elem(), false)
						Expect(err).NotTo(HaveOccurred())
						Expect(tag).To(Equal(yaml_STR_TAG))
						Expect(intf).To(Equal([]byte("abcdefg")))
					})
				})
			})

			It("fails to resolve a pointer", func() {
				aString := ""
				pString := &aString
				v := reflect.ValueOf(&pString)
				event.value = []byte("abc")

				_, err := resolve(event, v.Elem(), false)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("Unknown resolution for 'abc' using <*string Value> at line 0, column 0"))
			})
		})

		Context("Not an implicit event && no tag", func() {
			It("bool returns a string", func() {
				event.value = []byte("on")

				tag, result := resolveInterface(event, false)
				Expect(result).To(Equal("on"))
				Expect(tag).To(Equal(""))
			})

			It("number returns a string", func() {
				event.value = []byte("1234")

				tag, result := resolveInterface(event, false)
				Expect(result).To(Equal("1234"))
				Expect(tag).To(Equal(""))
			})

			It("returns the empty string", func() {
				event.value = []byte("")
				// event.implicit = true

				tag, result := resolveInterface(event, false)
				Expect(result).To(Equal(""))
				Expect(tag).To(Equal(""))
			})
		})
	})
})
