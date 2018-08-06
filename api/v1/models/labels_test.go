package models

import (
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LabelSuite struct{}

var _ = Suite(&LabelSuite{})

func (b *LabelSuite) TestsLabelsGetMap(c *C) {
	labels := models.Labels{
		"k8s:zgroup=testapp",
		"k8s:appSecond=true",
		"k8s:testNew=mynewvalue=true",
	}
	lblMap := labels.GetMap()

	expectedOutPut := map[string]string{
		"zgroup":    "testapp",
		"appSecond": "true",
		"testNew":   "mynewvalue=true",
	}
	c.Assert(lblMap, DeepEquals, expectedOutPut)
}
