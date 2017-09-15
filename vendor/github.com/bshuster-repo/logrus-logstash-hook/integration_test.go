package logrustash_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/sirupsen/logrus"
)

func TestTimestampFormatKitchen(t *testing.T) {
	log := logrus.New()
	buffer := bytes.NewBufferString("")
	hook := logrustash.New(buffer, logrustash.LogstashFormatter{
		Formatter: &logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime: "@timestamp",
				logrus.FieldKeyMsg:  "message",
			},
			TimestampFormat: time.Kitchen,
		},
		Fields: logrus.Fields{"HOSTNAME": "localhost", "USERNAME": "root"},
	})
	log.Hooks.Add(hook)

	log.Error("this is an error message!")
	mTime := time.Now()
	expected := fmt.Sprintf(`{"@timestamp":"%s","HOSTNAME":"localhost","USERNAME":"root","level":"error","message":"this is an error message!"}
`, mTime.Format(time.Kitchen))
	if buffer.String() != expected {
		t.Errorf("expected JSON to be '%#v' but got '%#v'", expected, buffer.String())
	}
}

func TestTextFormatLogstash(t *testing.T) {
	log := logrus.New()
	buffer := bytes.NewBufferString("")
	hook := logrustash.New(buffer, logrustash.LogstashFormatter{
		Formatter: &logrus.TextFormatter{
			TimestampFormat: time.Kitchen,
		},
		Fields: logrus.Fields{"HOSTNAME": "localhost", "USERNAME": "root"},
	})
	log.Hooks.Add(hook)

	log.Warning("this is a warning message!")
	mTime := time.Now()
	expected := fmt.Sprintf(`time="%s" level=warning msg="this is a warning message!" HOSTNAME=localhost USERNAME=root 
`, mTime.Format(time.Kitchen))
	if buffer.String() != expected {
		t.Errorf("expected JSON to be '%#v' but got '%#v'", expected, buffer.String())
	}
}

// UDP will never fail because it's connectionless.
// That's why I am using it for this integration tests just to make sure
// it won't fail when a data is written.
func TestUDPWritter(t *testing.T) {
	log := logrus.New()
	conn, err := net.Dial("udp", ":8282")
	if err != nil {
		t.Errorf("expected Dial to not return error: %s", err)
	}
	hook := logrustash.New(conn, &logrus.JSONFormatter{})
	log.Hooks.Add(hook)

	log.Info("this is an information message")
}
