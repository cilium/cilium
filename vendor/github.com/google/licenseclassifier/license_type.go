// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package licenseclassifier

// *** NOTE: Update this file when adding a new license. You need to:
//
//   1. Add the canonical name to the list, and
//   2. Categorize the license.

import "github.com/google/licenseclassifier/internal/sets"

// Canonical names of the licenses.
const (
	// The names come from the https://spdx.org/licenses website, and are
	// also the filenames of the licenses in licenseclassifier/licenses.
	AFL11                       = "AFL-1.1"
	AFL12                       = "AFL-1.2"
	AFL20                       = "AFL-2.0"
	AFL21                       = "AFL-2.1"
	AFL30                       = "AFL-3.0"
	AGPL10                      = "AGPL-1.0"
	AGPL30                      = "AGPL-3.0"
	Apache10                    = "Apache-1.0"
	Apache11                    = "Apache-1.1"
	Apache20                    = "Apache-2.0"
	APSL10                      = "APSL-1.0"
	APSL11                      = "APSL-1.1"
	APSL12                      = "APSL-1.2"
	APSL20                      = "APSL-2.0"
	Artistic10cl8               = "Artistic-1.0-cl8"
	Artistic10Perl              = "Artistic-1.0-Perl"
	Artistic10                  = "Artistic-1.0"
	Artistic20                  = "Artistic-2.0"
	BCL                         = "BCL"
	Beerware                    = "Beerware"
	BSD2ClauseFreeBSD           = "BSD-2-Clause-FreeBSD"
	BSD2ClauseNetBSD            = "BSD-2-Clause-NetBSD"
	BSD2Clause                  = "BSD-2-Clause"
	BSD3ClauseAttribution       = "BSD-3-Clause-Attribution"
	BSD3ClauseClear             = "BSD-3-Clause-Clear"
	BSD3ClauseLBNL              = "BSD-3-Clause-LBNL"
	BSD3Clause                  = "BSD-3-Clause"
	BSD4Clause                  = "BSD-4-Clause"
	BSD4ClauseUC                = "BSD-4-Clause-UC"
	BSDProtection               = "BSD-Protection"
	BSL10                       = "BSL-1.0"
	CC010                       = "CC0-1.0"
	CCBY10                      = "CC-BY-1.0"
	CCBY20                      = "CC-BY-2.0"
	CCBY25                      = "CC-BY-2.5"
	CCBY30                      = "CC-BY-3.0"
	CCBY40                      = "CC-BY-4.0"
	CCBYNC10                    = "CC-BY-NC-1.0"
	CCBYNC20                    = "CC-BY-NC-2.0"
	CCBYNC25                    = "CC-BY-NC-2.5"
	CCBYNC30                    = "CC-BY-NC-3.0"
	CCBYNC40                    = "CC-BY-NC-4.0"
	CCBYNCND10                  = "CC-BY-NC-ND-1.0"
	CCBYNCND20                  = "CC-BY-NC-ND-2.0"
	CCBYNCND25                  = "CC-BY-NC-ND-2.5"
	CCBYNCND30                  = "CC-BY-NC-ND-3.0"
	CCBYNCND40                  = "CC-BY-NC-ND-4.0"
	CCBYNCSA10                  = "CC-BY-NC-SA-1.0"
	CCBYNCSA20                  = "CC-BY-NC-SA-2.0"
	CCBYNCSA25                  = "CC-BY-NC-SA-2.5"
	CCBYNCSA30                  = "CC-BY-NC-SA-3.0"
	CCBYNCSA40                  = "CC-BY-NC-SA-4.0"
	CCBYND10                    = "CC-BY-ND-1.0"
	CCBYND20                    = "CC-BY-ND-2.0"
	CCBYND25                    = "CC-BY-ND-2.5"
	CCBYND30                    = "CC-BY-ND-3.0"
	CCBYND40                    = "CC-BY-ND-4.0"
	CCBYSA10                    = "CC-BY-SA-1.0"
	CCBYSA20                    = "CC-BY-SA-2.0"
	CCBYSA25                    = "CC-BY-SA-2.5"
	CCBYSA30                    = "CC-BY-SA-3.0"
	CCBYSA40                    = "CC-BY-SA-4.0"
	CDDL10                      = "CDDL-1.0"
	CDDL11                      = "CDDL-1.1"
	CommonsClause               = "Commons-Clause"
	CPAL10                      = "CPAL-1.0"
	CPL10                       = "CPL-1.0"
	eGenix                      = "eGenix"
	EPL10                       = "EPL-1.0"
	EPL20                       = "EPL-2.0"
	EUPL10                      = "EUPL-1.0"
	EUPL11                      = "EUPL-1.1"
	Facebook2Clause             = "Facebook-2-Clause"
	Facebook3Clause             = "Facebook-3-Clause"
	FacebookExamples            = "Facebook-Examples"
	FreeImage                   = "FreeImage"
	FTL                         = "FTL"
	GPL10                       = "GPL-1.0"
	GPL20                       = "GPL-2.0"
	GPL20withautoconfexception  = "GPL-2.0-with-autoconf-exception"
	GPL20withbisonexception     = "GPL-2.0-with-bison-exception"
	GPL20withclasspathexception = "GPL-2.0-with-classpath-exception"
	GPL20withfontexception      = "GPL-2.0-with-font-exception"
	GPL20withGCCexception       = "GPL-2.0-with-GCC-exception"
	GPL30                       = "GPL-3.0"
	GPL30withautoconfexception  = "GPL-3.0-with-autoconf-exception"
	GPL30withGCCexception       = "GPL-3.0-with-GCC-exception"
	GUSTFont                    = "GUST-Font-License"
	ImageMagick                 = "ImageMagick"
	IPL10                       = "IPL-1.0"
	ISC                         = "ISC"
	LGPL20                      = "LGPL-2.0"
	LGPL21                      = "LGPL-2.1"
	LGPL30                      = "LGPL-3.0"
	LGPLLR                      = "LGPLLR"
	Libpng                      = "Libpng"
	Lil10                       = "Lil-1.0"
	LinuxOpenIB                 = "Linux-OpenIB"
	LPL102                      = "LPL-1.02"
	LPL10                       = "LPL-1.0"
	LPPL13c                     = "LPPL-1.3c"
	MIT                         = "MIT"
	MPL10                       = "MPL-1.0"
	MPL11                       = "MPL-1.1"
	MPL20                       = "MPL-2.0"
	MSPL                        = "MS-PL"
	NCSA                        = "NCSA"
	NPL10                       = "NPL-1.0"
	NPL11                       = "NPL-1.1"
	OFL11                       = "OFL-1.1"
	OpenSSL                     = "OpenSSL"
	OpenVision                  = "OpenVision"
	OSL10                       = "OSL-1.0"
	OSL11                       = "OSL-1.1"
	OSL20                       = "OSL-2.0"
	OSL21                       = "OSL-2.1"
	OSL30                       = "OSL-3.0"
	PHP301                      = "PHP-3.01"
	PHP30                       = "PHP-3.0"
	PIL                         = "PIL"
	PostgreSQL                  = "PostgreSQL"
	Python20complete            = "Python-2.0-complete"
	Python20                    = "Python-2.0"
	QPL10                       = "QPL-1.0"
	Ruby                        = "Ruby"
	SGIB10                      = "SGI-B-1.0"
	SGIB11                      = "SGI-B-1.1"
	SGIB20                      = "SGI-B-2.0"
	SISSL12                     = "SISSL-1.2"
	SISSL                       = "SISSL"
	Sleepycat                   = "Sleepycat"
	UnicodeTOU                  = "Unicode-TOU"
	UnicodeDFS2015              = "Unicode-DFS-2015"
	UnicodeDFS2016              = "Unicode-DFS-2016"
	Unlicense                   = "Unlicense"
	UPL10                       = "UPL-1.0"
	W3C19980720                 = "W3C-19980720"
	W3C20150513                 = "W3C-20150513"
	W3C                         = "W3C"
	WTFPL                       = "WTFPL"
	X11                         = "X11"
	Xnet                        = "Xnet"
	Zend20                      = "Zend-2.0"
	ZeroBSD                     = "0BSD"
	ZlibAcknowledgement         = "zlib-acknowledgement"
	Zlib                        = "Zlib"
	ZPL11                       = "ZPL-1.1"
	ZPL20                       = "ZPL-2.0"
	ZPL21                       = "ZPL-2.1"
)

var (
	// Licenses Categorized by Type

	// restricted - Licenses in this category require mandatory source
	// distribution if we ships a product that includes third-party code
	// protected by such a license.
	restrictedType = sets.NewStringSet(
		BCL,
		CCBYND10,
		CCBYND20,
		CCBYND25,
		CCBYND30,
		CCBYND40,
		CCBYSA10,
		CCBYSA20,
		CCBYSA25,
		CCBYSA30,
		CCBYSA40,
		GPL10,
		GPL20,
		GPL20withautoconfexception,
		GPL20withbisonexception,
		GPL20withclasspathexception,
		GPL20withfontexception,
		GPL20withGCCexception,
		GPL30,
		GPL30withautoconfexception,
		GPL30withGCCexception,
		LGPL20,
		LGPL21,
		LGPL30,
		NPL10,
		NPL11,
		OSL10,
		OSL11,
		OSL20,
		OSL21,
		OSL30,
		QPL10,
		Sleepycat,
	)

	// reciprocal - These licenses allow usage of software made available
	// under such licenses freely in *unmodified* form. If the third-party
	// source code is modified in any way these modifications to the
	// original third-party source code must be made available.
	reciprocalType = sets.NewStringSet(
		APSL10,
		APSL11,
		APSL12,
		APSL20,
		CDDL10,
		CDDL11,
		CPL10,
		EPL10,
		EPL20,
		FreeImage,
		IPL10,
		MPL10,
		MPL11,
		MPL20,
		Ruby,
	)

	// notice - These licenses contain few restrictions, allowing original
	// or modified third-party software to be shipped in any product
	// without endangering or encumbering our source code. All of the
	// licenses in this category do, however, have an "original Copyright
	// notice" or "advertising clause", wherein any external distributions
	// must include the notice or clause specified in the license.
	noticeType = sets.NewStringSet(
		AFL11,
		AFL12,
		AFL20,
		AFL21,
		AFL30,
		Apache10,
		Apache11,
		Apache20,
		Artistic10cl8,
		Artistic10Perl,
		Artistic10,
		Artistic20,
		BSL10,
		BSD2ClauseFreeBSD,
		BSD2ClauseNetBSD,
		BSD2Clause,
		BSD3ClauseAttribution,
		BSD3ClauseClear,
		BSD3ClauseLBNL,
		BSD3Clause,
		BSD4Clause,
		BSD4ClauseUC,
		BSDProtection,
		CCBY10,
		CCBY20,
		CCBY25,
		CCBY30,
		CCBY40,
		FTL,
		ISC,
		ImageMagick,
		Libpng,
		Lil10,
		LinuxOpenIB,
		LPL102,
		LPL10,
		MSPL,
		MIT,
		NCSA,
		OpenSSL,
		PHP301,
		PHP30,
		PIL,
		Python20,
		Python20complete,
		PostgreSQL,
		SGIB10,
		SGIB11,
		SGIB20,
		UnicodeDFS2015,
		UnicodeDFS2016,
		UnicodeTOU,
		UPL10,
		W3C19980720,
		W3C20150513,
		W3C,
		X11,
		Xnet,
		Zend20,
		ZlibAcknowledgement,
		Zlib,
		ZPL11,
		ZPL20,
		ZPL21,
	)

	// permissive - These licenses can be used in (relatively rare) cases
	// where third-party software is under a license (not "Public Domain"
	// or "free for any use" like 'unencumbered') that is even more lenient
	// than a 'notice' license. Use the 'permissive' license type when even
	// a copyright notice is not required for license compliance.
	permissiveType = sets.NewStringSet()

	// unencumbered - Licenses that basically declare that the code is "free for any use".
	unencumberedType = sets.NewStringSet(
		CC010,
		Unlicense,
		ZeroBSD,
	)

	// byexceptiononly - Licenses that are incompatible with all (or most)
	// uses in combination with our source code. Commercial third-party
	// packages that are purchased and licensed only for a specific use
	// fall into this category.
	byExceptionOnlyType = sets.NewStringSet(
		Beerware,
		OFL11,
		OpenVision,
	)

	// forbidden - Licenses that are forbidden to be used.
	forbiddenType = sets.NewStringSet(
		AGPL10,
		AGPL30,
		CCBYNC10,
		CCBYNC20,
		CCBYNC25,
		CCBYNC30,
		CCBYNC40,
		CCBYNCND10,
		CCBYNCND20,
		CCBYNCND25,
		CCBYNCND30,
		CCBYNCND40,
		CCBYNCSA10,
		CCBYNCSA20,
		CCBYNCSA25,
		CCBYNCSA30,
		CCBYNCSA40,
		CommonsClause,
		Facebook2Clause,
		Facebook3Clause,
		FacebookExamples,
		WTFPL,
	)

	// LicenseTypes is a set of the types of licenses Google recognizes.
	LicenseTypes = sets.NewStringSet(
		"restricted",
		"reciprocal",
		"notice",
		"permissive",
		"unencumbered",
		"by_exception_only",
	)
)

// LicenseType returns the type the license has.
func LicenseType(name string) string {
	switch {
	case restrictedType.Contains(name):
		return "restricted"
	case reciprocalType.Contains(name):
		return "reciprocal"
	case noticeType.Contains(name):
		return "notice"
	case permissiveType.Contains(name):
		return "permissive"
	case unencumberedType.Contains(name):
		return "unencumbered"
	case forbiddenType.Contains(name):
		return "FORBIDDEN"
	}
	return ""
}
