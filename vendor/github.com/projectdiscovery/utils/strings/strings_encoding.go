package stringsutil

import (
	"errors"

	"github.com/saintfish/chardet"
)

type EncodingType uint8

const (
	Unknown EncodingType = iota
	UTF8
	UTF16BE
	UTF16LE
	UTF32BE
	UTF32LE
	ISO85591
	ISO88592
	ISO88595
	ISO88596
	ISO88597
	ISO88598
	Windows1251
	Windows1256
	KOI8R
	ShiftJIS
	GB18030
	EUCJP
	EUCKR
	Big5
	ISO2022JP
	ISO2022KR
	ISO2022CN
	IBM424rtl
	IBM424ltr
	IBM420rtl
	IBM420ltr
)

var detector *chardet.Detector = chardet.NewTextDetector()

func DetectEncodingType(data interface{}) (EncodingType, error) {
	var (
		enc *chardet.Result
		err error
	)
	switch dd := data.(type) {
	case string:
		enc, err = detector.DetectBest([]byte(dd))
	case []byte:
		enc, err = detector.DetectBest(dd)
	default:
		return Unknown, errors.New("unsupported type")
	}

	if err != nil || enc == nil {
		return Unknown, err
	}

	switch enc.Charset {
	case "UTF-8":
		return UTF8, nil
	case "UTF-16BE":
		return UTF16BE, nil
	case "UTF-16LE":
		return UTF16LE, nil
	case "UTF-32BE":
		return UTF32BE, nil
	case "UTF-32LE":
		return UTF32LE, nil
	case "ISO-8859-1":
		return ISO85591, nil
	case "ISO-8859-2":
		return ISO88592, nil
	case "ISO-8859-5":
		return ISO88595, nil
	case "ISO-8859-6":
		return ISO88596, nil
	case "ISO-8859-7":
		return ISO88597, nil
	case "ISO-8859-8":
		return ISO88598, nil
	case "windows-1251":
		return Windows1251, nil
	case "windows-1256":
		return Windows1256, nil
	case "KOI8-R":
		return KOI8R, nil
	case "Shift_JIS":
		return ShiftJIS, nil
	case "GB18030":
		return GB18030, nil
	case "EUC-JP":
		return EUCJP, nil
	case "EUC-KR":
		return EUCKR, nil
	case "Big5":
		return Big5, nil
	case "ISO-2022-JP":
		return ISO2022JP, nil
	case "ISO-2022-KR":
		return ISO2022KR, nil
	case "ISO-2022-CN":
		return ISO2022CN, nil
	case "IBM424_rtl":
		return IBM424rtl, nil
	case "IBM424_ltr":
		return IBM424ltr, nil
	case "IBM420_rtl":
		return IBM420rtl, nil
	case "IBM420_ltr":
		return IBM420ltr, nil
	default:
		return Unknown, nil
	}
}
