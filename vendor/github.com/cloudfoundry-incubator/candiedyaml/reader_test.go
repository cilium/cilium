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
	// "fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/*
 * Test cases are stolen from
 * http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
 */

type test_case struct {
	title  string
	test   string
	result bool
}

var _ = Describe("Reader", func() {
	LONG := 100000

	Context("UTF8 Sequences", func() {
		utf8_sequences := []test_case{
			/* {"title", "test 1|test 2|...|test N!", (0 or 1)}, */

			{"a simple test", "'test' is '\xd0\xbf\xd1\x80\xd0\xbe\xd0\xb2\xd0\xb5\xd1\x80\xd0\xba\xd0\xb0' in Russian!", true},

			{"an empty line", "!", true},
			{"u-0 is a control character", "\x00!", false},
			{"u-80 is a control character", "\xc2\x80!", false},
			{"u-800 is valid", "\xe0\xa0\x80!", true},
			{"u-10000 is valid", "\xf0\x90\x80\x80!", true},
			{"5 bytes sequences are not allowed", "\xf8\x88\x80\x80\x80!", false},
			{"6 bytes sequences are not allowed", "\xfc\x84\x80\x80\x80\x80!", false},

			{"u-7f is a control character", "\x7f!", false},
			{"u-7FF is valid", "\xdf\xbf!", true},
			{"u-FFFF is a control character", "\xef\xbf\xbf!", false},
			{"u-1FFFFF is too large", "\xf7\xbf\xbf\xbf!", false},
			{"u-3FFFFFF is 5 bytes", "\xfb\xbf\xbf\xbf\xbf!", false},
			{"u-7FFFFFFF is 6 bytes", "\xfd\xbf\xbf\xbf\xbf\xbf!", false},

			{"u-D7FF", "\xed\x9f\xbf!", true},
			{"u-E000", "\xee\x80\x80!", true},
			{"u-FFFD", "\xef\xbf\xbd!", true},
			{"u-10FFFF", "\xf4\x8f\xbf\xbf!", true},
			{"u-110000", "\xf4\x90\x80\x80!", false},

			{"first continuation byte", "\x80!", false},
			{"last continuation byte", "\xbf!", false},

			{"2 continuation bytes", "\x80\xbf!", false},
			{"3 continuation bytes", "\x80\xbf\x80!", false},
			{"4 continuation bytes", "\x80\xbf\x80\xbf!", false},
			{"5 continuation bytes", "\x80\xbf\x80\xbf\x80!", false},
			{"6 continuation bytes", "\x80\xbf\x80\xbf\x80\xbf!", false},
			{"7 continuation bytes", "\x80\xbf\x80\xbf\x80\xbf\x80!", false},

			{"sequence of all 64 possible continuation bytes",
				"\x80|\x81|\x82|\x83|\x84|\x85|\x86|\x87|\x88|\x89|\x8a|\x8b|\x8c|\x8d|\x8e|\x8f|" +
					"\x90|\x91|\x92|\x93|\x94|\x95|\x96|\x97|\x98|\x99|\x9a|\x9b|\x9c|\x9d|\x9e|\x9f|" +
					"\xa0|\xa1|\xa2|\xa3|\xa4|\xa5|\xa6|\xa7|\xa8|\xa9|\xaa|\xab|\xac|\xad|\xae|\xaf|" +
					"\xb0|\xb1|\xb2|\xb3|\xb4|\xb5|\xb6|\xb7|\xb8|\xb9|\xba|\xbb|\xbc|\xbd|\xbe|\xbf!", false},
			{"32 first bytes of 2-byte sequences {0xc0-0xdf}",
				"\xc0 |\xc1 |\xc2 |\xc3 |\xc4 |\xc5 |\xc6 |\xc7 |\xc8 |\xc9 |\xca |\xcb |\xcc |\xcd |\xce |\xcf |" +
					"\xd0 |\xd1 |\xd2 |\xd3 |\xd4 |\xd5 |\xd6 |\xd7 |\xd8 |\xd9 |\xda |\xdb |\xdc |\xdd |\xde |\xdf !", false},
			{"16 first bytes of 3-byte sequences {0xe0-0xef}",
				"\xe0 |\xe1 |\xe2 |\xe3 |\xe4 |\xe5 |\xe6 |\xe7 |\xe8 |\xe9 |\xea |\xeb |\xec |\xed |\xee |\xef !", false},
			{"8 first bytes of 4-byte sequences {0xf0-0xf7}", "\xf0 |\xf1 |\xf2 |\xf3 |\xf4 |\xf5 |\xf6 |\xf7 !", false},
			{"4 first bytes of 5-byte sequences {0xf8-0xfb}", "\xf8 |\xf9 |\xfa |\xfb !", false},
			{"2 first bytes of 6-byte sequences {0xfc-0xfd}", "\xfc |\xfd !", false},

			{"sequences with last byte missing {u-0}",
				"\xc0|\xe0\x80|\xf0\x80\x80|\xf8\x80\x80\x80|\xfc\x80\x80\x80\x80!", false},
			{"sequences with last byte missing {u-...FF}",
				"\xdf|\xef\xbf|\xf7\xbf\xbf|\xfb\xbf\xbf\xbf|\xfd\xbf\xbf\xbf\xbf!", false},

			{"impossible bytes", "\xfe|\xff|\xfe\xfe\xff\xff!", false},

			{"overlong sequences {u-2f}",
				"\xc0\xaf|\xe0\x80\xaf|\xf0\x80\x80\xaf|\xf8\x80\x80\x80\xaf|\xfc\x80\x80\x80\x80\xaf!", false},

			{"maximum overlong sequences",
				"\xc1\xbf|\xe0\x9f\xbf|\xf0\x8f\xbf\xbf|\xf8\x87\xbf\xbf\xbf|\xfc\x83\xbf\xbf\xbf\xbf!", false},

			{"overlong representation of the NUL character",
				"\xc0\x80|\xe0\x80\x80|\xf0\x80\x80\x80|\xf8\x80\x80\x80\x80|\xfc\x80\x80\x80\x80\x80!", false},

			{"single UTF-16 surrogates",
				"\xed\xa0\x80|\xed\xad\xbf|\xed\xae\x80|\xed\xaf\xbf|\xed\xb0\x80|\xed\xbe\x80|\xed\xbf\xbf!", false},

			{"paired UTF-16 surrogates",
				"\xed\xa0\x80\xed\xb0\x80|\xed\xa0\x80\xed\xbf\xbf|\xed\xad\xbf\xed\xb0\x80|" +
					"\xed\xad\xbf\xed\xbf\xbf|\xed\xae\x80\xed\xb0\x80|\xed\xae\x80\xed\xbf\xbf|" +
					"\xed\xaf\xbf\xed\xb0\x80|\xed\xaf\xbf\xed\xbf\xbf!", false},

			{"other illegal code positions", "\xef\xbf\xbe|\xef\xbf\xbf!", false},
		}

		check_sequence := func(tc test_case) {
			It(tc.title, func() {
				start := 0
				end := start
				bytes := []byte(tc.test)

				for {
					for bytes[end] != '|' && bytes[end] != '!' {
						end++
					}

					parser := yaml_parser_t{}
					yaml_parser_initialize(&parser)
					yaml_parser_set_input_string(&parser, bytes)
					result := yaml_parser_update_buffer(&parser, end-start)
					Expect(result).To(Equal(tc.result))
					// outcome := '+'
					// if result != tc.result {
					// 	outcome = '-'
					// }
					// fmt.Printf("\t\t %c %s", outcome, tc.title)
					// if parser.error == yaml_NO_ERROR {
					// 	fmt.Printf("(no error)\n")
					// } else if parser.error == yaml_READER_ERROR {
					// 	if parser.problem_value != -1 {
					// 		fmt.Printf("(reader error: %s: #%X at %d)\n",
					// 			parser.problem, parser.problem_value, parser.problem_offset)
					// 	} else {
					// 		fmt.Printf("(reader error: %s: at %d)\n",
					// 			parser.problem, parser.problem_offset)
					// 	}
					// }

					if bytes[end] == '!' {
						break
					}

					end++
					start = end
					yaml_parser_delete(&parser)
				}
			})
		}

		for _, test := range utf8_sequences {
			check_sequence(test)
		}
	})

	Context("BOMs", func() {
		boms := []test_case{
			/* {"title", "test!", lenth}, */
			{"no bom (utf-8)", "Hi is \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82!", true},
			{"bom (utf-8)", "\xef\xbb\xbfHi is \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82!", true},
			{"bom (utf-16-le)", "\xff\xfeH\x00i\x00 \x00i\x00s\x00 \x00\x1f\x04@\x04" + "8\x04" + "2\x04" + "5\x04" + "B\x04!", true},
			{"bom (utf-16-be)", "\xfe\xff\x00H\x00i\x00 \x00i\x00s\x00 \x04\x1f\x04@\x04" + "8\x04" + "2\x04" + "5\x04" + "B!", true},
		}

		check_bom := func(tc test_case) {
			It(tc.title, func() {
				start := 0
				end := start
				bytes := []byte(tc.test)

				for bytes[end] != '!' {
					end++
				}

				parser := yaml_parser_t{}
				yaml_parser_initialize(&parser)
				yaml_parser_set_input_string(&parser, bytes[:end-start])
				result := yaml_parser_update_buffer(&parser, end-start)
				Expect(result).To(Equal(tc.result))
				yaml_parser_delete(&parser)
			})
		}

		for _, test := range boms {
			check_bom(test)
		}

	})

	Context("Long UTF8", func() {
		It("parses properly", func() {
			buffer := make([]byte, 0, 3+LONG*2)
			buffer = append(buffer, '\xef', '\xbb', '\xbf')
			for j := 0; j < LONG; j++ {
				if j%2 == 1 {
					buffer = append(buffer, '\xd0', '\x90')
				} else {
					buffer = append(buffer, '\xd0', '\xaf')
				}
			}
			parser := yaml_parser_t{}
			yaml_parser_initialize(&parser)
			yaml_parser_set_input_string(&parser, buffer)

			for k := 0; k < LONG; k++ {
				if parser.unread == 0 {
					updated := yaml_parser_update_buffer(&parser, 1)
					Expect(updated).To(BeTrue())
					// printf("\treader error: %s at %d\n", parser.problem, parser.problem_offset);
				}
				Expect(parser.unread).NotTo(Equal(0))
				// printf("\tnot enough characters at %d\n", k);
				var ch0, ch1 byte
				if k%2 == 1 {
					ch0 = '\xd0'
					ch1 = '\x90'
				} else {
					ch0 = '\xd0'
					ch1 = '\xaf'
				}
				Expect(parser.buffer[parser.buffer_pos]).To(Equal(ch0))
				Expect(parser.buffer[parser.buffer_pos+1]).To(Equal(ch1))
				// printf("\tincorrect UTF-8 sequence: %X %X instead of %X %X\n",
				//         (int)parser.buffer.pointer[0], (int)parser.buffer.pointer[1],
				//         (int)ch0, (int)ch1);

				parser.buffer_pos += 2
				parser.unread -= 1
			}
			updated := yaml_parser_update_buffer(&parser, 1)
			Expect(updated).To(BeTrue())
			// printf("\treader error: %s at %d\n", parser.problem, parser.problem_offset);
			yaml_parser_delete(&parser)
		})
	})

	Context("Long UTF16", func() {
		It("parses properly", func() {
			buffer := make([]byte, 0, 2+LONG*2)
			buffer = append(buffer, '\xff', '\xfe')
			for j := 0; j < LONG; j++ {
				if j%2 == 1 {
					buffer = append(buffer, '\x10', '\x04')
				} else {
					buffer = append(buffer, '/', '\x04')
				}
			}
			parser := yaml_parser_t{}
			yaml_parser_initialize(&parser)
			yaml_parser_set_input_string(&parser, buffer)

			for k := 0; k < LONG; k++ {
				if parser.unread == 0 {
					updated := yaml_parser_update_buffer(&parser, 1)
					Expect(updated).To(BeTrue())
					// printf("\treader error: %s at %d\n", parser.problem, parser.problem_offset);
				}
				Expect(parser.unread).NotTo(Equal(0))
				// printf("\tnot enough characters at %d\n", k);
				var ch0, ch1 byte
				if k%2 == 1 {
					ch0 = '\xd0'
					ch1 = '\x90'
				} else {
					ch0 = '\xd0'
					ch1 = '\xaf'
				}
				Expect(parser.buffer[parser.buffer_pos]).To(Equal(ch0))
				Expect(parser.buffer[parser.buffer_pos+1]).To(Equal(ch1))
				// printf("\tincorrect UTF-8 sequence: %X %X instead of %X %X\n",
				//         (int)parser.buffer.pointer[0], (int)parser.buffer.pointer[1],
				//         (int)ch0, (int)ch1);

				parser.buffer_pos += 2
				parser.unread -= 1
			}
			updated := yaml_parser_update_buffer(&parser, 1)
			Expect(updated).To(BeTrue())
			// printf("\treader error: %s at %d\n", parser.problem, parser.problem_offset);
			yaml_parser_delete(&parser)
		})
	})
})
