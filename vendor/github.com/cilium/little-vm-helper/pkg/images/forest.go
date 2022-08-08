package images

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// we organize images in a forest, i.e., a set of trees

// ImageForest is a set of images forming a forest (i.e., a set of trees)
type ImageForest struct {
	imagesDir string
	confs     map[string]*ImgConf
	children  map[string][]string
}

// NewImageForest creates a new image forest
// it will create a new image directory if it does not exist
// if saveConfigFileInDir is set, a serialized version of the configuration
// file will be saved in the image directory
func NewImageForest(conf *ImagesConf, saveConfFile bool) (*ImageForest, error) {
	// image name -> ImageConf
	confs := make(map[string]*ImgConf, len(conf.Images))
	// name -> parent name (if parent exists)
	parent := make(map[string]string)

	// check that there are no duplicate images, and populate the confs, and parent maps
	for i := range conf.Images {
		icnf := &conf.Images[i]
		if _, ok := confs[icnf.Name]; ok {
			return nil, fmt.Errorf("duplicate image name: %s", icnf.Name)
		}
		confs[icnf.Name] = icnf
		if icnf.Parent != "" {
			parent[icnf.Name] = icnf.Parent
		}
	}

	// using the parent map, form the children map
	children := make(map[string][]string)
	for child, parent := range parent {
		if _, ok := confs[parent]; !ok {
			// NB: in some cases, we want to build an iamge based on
			// another image, without including the former in our
			// configuration.
			continue
			// return nil, fmt.Errorf("image '%s' specified as parent, but it is not defined", parent)
		}
		children[parent] = append(children[parent], child)
	}

	imagesDir := conf.Dir
	err := os.MkdirAll(imagesDir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	if saveConfFile {
		confb, err := json.Marshal(conf)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(filepath.Join(conf.Dir, DefaultConfFile), confb, 0666)
		if err != nil {
			return nil, fmt.Errorf("error writing configuration: %w", err)
		}
	}

	return &ImageForest{
		imagesDir: imagesDir,
		confs:     confs,
		children:  children,
	}, nil
}

// ImageFilename returns the filename of an image
func (f *ImageForest) ImageFilename(image string) (string, error) {
	if _, ok := f.confs[image]; !ok {
		return "", fmt.Errorf("no configuration for image '%s'", image)
	}

	return f.imageFilename(image), nil
}

func (f *ImageForest) imageFilename(image string) string {
	return filepath.Join(f.imagesDir, image)
}

// getDependencies returns the dependencies of an image, i.e., what images need to be build before it
func (f *ImageForest) getDependencies(image string) ([]string, error) {
	var ret []string
	cnf, ok := f.confs[image]
	if !ok {
		return ret, fmt.Errorf("cannot build dependencies for image %s, because image does not exist ", image)
	}

	parent := cnf.Parent
	for parent != "" {
		// NB: we have checked that all parents exist in NewImageForest
		cnfParent := f.confs[parent]
		ret = append(ret, parent)
		parent = cnfParent.Parent
	}

	// reverse ret slice
	for i, j := 0, len(ret)-1; i < j; i, j = i+1, j-1 {
		ret[i], ret[j] = ret[j], ret[i]
	}
	return ret, nil
}

func (f *ImageForest) IsLeafImage(i string) bool {
	_, hasChidren := f.children[i]
	return !hasChidren
}

func (f *ImageForest) LeafImages() []string {
	ret := make([]string, 0)
	for i, _ := range f.confs {
		if f.IsLeafImage(i) {
			ret = append(ret, i)
		}
	}
	return ret
}

func (f *ImageForest) isRootImage(cnf *ImgConf) bool {
	if cnf.Parent == "" {
		return true
		// if there is no parent, this is a root image
	} else if _, ok := f.children[cnf.Parent]; !ok {
		// if there is a parent, but it's not in our
		// configuration, also treat this as a root image.
		return true
	}

	return false
}

func (f *ImageForest) IsRootImage(image string) (bool, error) {
	cnf, ok := f.confs[image]
	if !ok {
		return false, fmt.Errorf("image `%s` does not exist in forest", image)
	}
	return f.isRootImage(cnf), nil
}

// returns parent image, or ""
func (f *ImageForest) getParent(image string) string {
	cnf := f.confs[image]
	if f.isRootImage(cnf) {
		return ""
	}
	return cnf.Parent
}

func (f *ImageForest) RootImages() []string {
	ret := make([]string, 0)
	for i, cnf := range f.confs {
		if f.isRootImage(cnf) {
			ret = append(ret, i)
		}
	}

	return ret
}
