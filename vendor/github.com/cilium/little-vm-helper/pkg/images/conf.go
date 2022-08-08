package images

// ImgConf is the configuration of an image
type ImgConf struct {
	// Name of the image
	Name string `json:"name"`
	// Parent is the name parent image (or "" if image does not have a parent)
	Parent string `json:"parent,omitempty"`
	// Packages is the list of packages contained in the image
	Packages []string `json:"packages"`
	// Actions is a list of additional actions for building the image.
	// Order will be maintained during execution.
	Actions []Action `json:"actions,omitempty"`
}

// ImagesConf is the configuration of a set of images
type ImagesConf struct {
	// ImageDir is the directory for the images
	Dir string
	// Images is the configuration for all images
	Images []ImgConf
}
