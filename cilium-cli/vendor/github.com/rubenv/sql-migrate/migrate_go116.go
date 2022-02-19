// +build go1.16

package migrate

import (
	"embed"
	"net/http"
)

// A set of migrations loaded from an go1.16 embed.FS

type EmbedFileSystemMigrationSource struct {
	FileSystem embed.FS

	Root string
}

var _ MigrationSource = (*EmbedFileSystemMigrationSource)(nil)

func (f EmbedFileSystemMigrationSource) FindMigrations() ([]*Migration, error) {
	return findMigrations(http.FS(f.FileSystem), f.Root)
}
