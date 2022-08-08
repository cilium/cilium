package images

import "github.com/sirupsen/logrus"

// StepConf is common step configuration
type StepConf struct {
	imagesDir string
	imgCnf    *ImgConf
	log       *logrus.Logger
}
