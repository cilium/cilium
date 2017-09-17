# Changelog

## 1.0

 * Remove the old API: `NewConnWith`, `WithPrefix` and etc and move to a simple `New` function.
 * Prefix is no longer supported in this package.
 * Change the Hook structure to have only two members: `logrus.Formatter` and `io.Writer`.

## 0.4

 * Update the name of the package from `logrus_logstash` to `logrustash`
 * Add TimeFormat to Hook
 * Replace the old logrus package path: `github.com/Sirupsen/logrus` with `github.com/sirupsen/logrus` 

## 0.3

 * Fix the Logstash format to set `@version` to `"1"`
 * Add unit-tests to logstash.go
 * Remove the assert package
 * Add prefix filtering

## Before that (major changes)

 * Update LICENSE to MIT from GPL
