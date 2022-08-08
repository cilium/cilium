package images

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/packer-plugin-sdk/multistep"
	"github.com/sirupsen/logrus"
)

// doBuildImageDryRun just creates an empty file for the image.
func (f *ImageForest) doBuildImageDryRun(image string) error {
	_, ok := f.confs[image]
	if !ok {
		return fmt.Errorf("building image '%s' failed, configuration not found", image)
	}

	fname := f.imageFilename(image)
	file, err := os.Create(fname)
	defer file.Close()

	return err
}

// merge act2 to act1, or return an error
func mergeSteps(step1, step2 multistep.Step) error {
	mergable, ok := step1.(interface {
		Merge(step multistep.Step) error
	})
	if !ok {
		return fmt.Errorf("step1 (%v) not mergable", step1)
	}

	if err := mergable.Merge(step2); err != nil {
		return err
	}

	return nil
}

func (f *ImageForest) doBuildImage(
	ctx context.Context,
	log *logrus.Logger,
	image string,
	merge bool,
) error {
	cnf, ok := f.confs[image]
	if !ok {
		return fmt.Errorf("building image '%s' failed, configuration not found", image)
	}

	stepConf := &StepConf{
		imagesDir: f.imagesDir,
		imgCnf:    cnf,
		log:       log,
	}

	state := new(multistep.BasicStateBag)
	steps := make([]multistep.Step, 1, 1+len(cnf.Actions))
	steps[0] = NewCreateImage(stepConf)
	for i := 0; i < len(cnf.Actions); i++ {
		next := cnf.Actions[i].Op.ToStep(stepConf)
		prev := steps[len(steps)-1]
		if merge && mergeSteps(prev, next) == nil {
			continue
		}
		steps = append(steps, next)
	}

	runner := &multistep.BasicRunner{Steps: steps}
	runner.Run(ctx, state)
	err := state.Get("err")
	if err != nil {
		imgFname := f.imageFilename(image)
		log.Warnf("image file '%s' not deleted so that it can be inspected", imgFname)
		return err.(error)
	}
	return nil
}
