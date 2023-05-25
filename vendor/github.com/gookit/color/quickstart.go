package color

/*************************************************************
 * quick use color print message
 *************************************************************/

// Redp print message with Red color
func Redp(a ...any) { Red.Print(a...) }

// Redf print message with Red color
func Redf(format string, a ...any) { Red.Printf(format, a...) }

// Redln print message line with Red color
func Redln(a ...any) { Red.Println(a...) }

// Bluep print message with Blue color
func Bluep(a ...any) { Blue.Print(a...) }

// Bluef print message with Blue color
func Bluef(format string, a ...any) { Blue.Printf(format, a...) }

// Blueln print message line with Blue color
func Blueln(a ...any) { Blue.Println(a...) }

// Cyanp print message with Cyan color
func Cyanp(a ...any) { Cyan.Print(a...) }

// Cyanf print message with Cyan color
func Cyanf(format string, a ...any) { Cyan.Printf(format, a...) }

// Cyanln print message line with Cyan color
func Cyanln(a ...any) { Cyan.Println(a...) }

// Grayp print message with Gray color
func Grayp(a ...any) { Gray.Print(a...) }

// Grayf print message with Gray color
func Grayf(format string, a ...any) { Gray.Printf(format, a...) }

// Grayln print message line with Gray color
func Grayln(a ...any) { Gray.Println(a...) }

// Greenp print message with Green color
func Greenp(a ...any) { Green.Print(a...) }

// Greenf print message with Green color
func Greenf(format string, a ...any) { Green.Printf(format, a...) }

// Greenln print message line with Green color
func Greenln(a ...any) { Green.Println(a...) }

// Yellowp print message with Yellow color
func Yellowp(a ...any) { Yellow.Print(a...) }

// Yellowf print message with Yellow color
func Yellowf(format string, a ...any) { Yellow.Printf(format, a...) }

// Yellowln print message line with Yellow color
func Yellowln(a ...any) { Yellow.Println(a...) }

// Magentap print message with Magenta color
func Magentap(a ...any) { Magenta.Print(a...) }

// Magentaf print message with Magenta color
func Magentaf(format string, a ...any) { Magenta.Printf(format, a...) }

// Magentaln print message line with Magenta color
func Magentaln(a ...any) { Magenta.Println(a...) }

/*************************************************************
 * quick use style print message
 *************************************************************/

// Infop print message with Info color
func Infop(a ...any) { Info.Print(a...) }

// Infof print message with Info style
func Infof(format string, a ...any) { Info.Printf(format, a...) }

// Infoln print message with Info style
func Infoln(a ...any) { Info.Println(a...) }

// Successp print message with success color
func Successp(a ...any) { Success.Print(a...) }

// Successf print message with success style
func Successf(format string, a ...any) { Success.Printf(format, a...) }

// Successln print message with success style
func Successln(a ...any) { Success.Println(a...) }

// Errorp print message with Error color
func Errorp(a ...any) { Error.Print(a...) }

// Errorf print message with Error style
func Errorf(format string, a ...any) { Error.Printf(format, a...) }

// Errorln print message with Error style
func Errorln(a ...any) { Error.Println(a...) }

// Warnp print message with Warn color
func Warnp(a ...any) { Warn.Print(a...) }

// Warnf print message with Warn style
func Warnf(format string, a ...any) { Warn.Printf(format, a...) }

// Warnln print message with Warn style
func Warnln(a ...any) { Warn.Println(a...) }
