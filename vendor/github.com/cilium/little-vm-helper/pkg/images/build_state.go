package images

import (
	"fmt"
	"os"
)

// buildState is an internal structure for bookkeeping when building a set of images
type buildState struct {
	f         *ImageForest
	bldConf   *BuildConf
	bldResult BuilderResult
}

func newBuildState(f *ImageForest, cnf *BuildConf) *buildState {
	return &buildState{
		f:       f,
		bldConf: cnf,
		bldResult: BuilderResult{
			ImageResults: make(map[string]BuildImageResult),
		},
	}
}

// buildImage will build an image and update the results state
func (b *buildState) buildImage(image string) BuildImageResult {
	res := b.doBuildImage(image)
	b.bldResult.ImageResults[image] = res
	return res
}

// skipRebuild checks if an image is not required to be build because it
// already exists.
func (b *buildState) skipRebuild(image string) BuildImageResult {
	imageFname, err := b.f.ImageFilename(image)
	if err != nil {
		return BuildImageResult{Error: err}
	}

	if fi, err := os.Stat(imageFname); err == nil {
		mode := fi.Mode()
		if !mode.IsRegular() {
			// NB: we could do something like os.RemoveAll() here
			// but this is a weird case, so we just bail out
			return BuildImageResult{
				Error: fmt.Errorf("'%s' is not a regular file. Bailing out.", imageFname),
			}
		}

		if b.bldConf.ForceRebuild {
			os.Remove(imageFname)
			return BuildImageResult{
				CachedImageDeleted: fmt.Sprintf("image '%s' was deleted because a rebuild was forced", imageFname),
			}
		}

		if !b.bldConf.DryRun && fi.Size() == 0 {
			os.Remove(imageFname)
			return BuildImageResult{
				CachedImageDeleted: fmt.Sprintf("image '%s' was an empty file, and this was not a dry run", imageFname),
			}
		}

		if parent := b.f.getParent(image); parent != "" && !b.bldResult.ImageResults[parent].CachedImageUsed {
			os.Remove(imageFname)
			return BuildImageResult{
				CachedImageDeleted: fmt.Sprintf("image '%s' existed, but parent '%s' did not use the cache", imageFname, parent),
			}
		}

		return BuildImageResult{
			CachedImageUsed: true,
		}
	}
	// todo: we might want to check the error that this is an actual ENOENT error
	return BuildImageResult{}
}
