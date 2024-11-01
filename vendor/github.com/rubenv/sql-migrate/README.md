# sql-migrate

> SQL Schema migration tool for [Go](https://golang.org/). Based on [gorp](https://github.com/go-gorp/gorp) and [goose](https://bitbucket.org/liamstask/goose).

[![Test](https://github.com/rubenv/sql-migrate/actions/workflows/test.yml/badge.svg)](https://github.com/rubenv/sql-migrate/actions/workflows/test.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/rubenv/sql-migrate.svg)](https://pkg.go.dev/github.com/rubenv/sql-migrate)

## Features

- Usable as a CLI tool or as a library
- Supports SQLite, PostgreSQL, MySQL, MSSQL and Oracle databases (through [gorp](https://github.com/go-gorp/gorp))
- Can embed migrations into your application
- Migrations are defined with SQL for full flexibility
- Atomic migrations
- Up/down migrations to allow rollback
- Supports multiple database types in one project
- Works great with other libraries such as [sqlx](https://jmoiron.github.io/sqlx/)
- Supported on go1.13+

## Installation

To install the library and command line program, use the following:

```bash
go get -v github.com/rubenv/sql-migrate/...
```

For Go version from 1.18, use:

```bash
go install github.com/rubenv/sql-migrate/...@latest
```

## Usage

### As a standalone tool

```
$ sql-migrate --help
usage: sql-migrate [--version] [--help] <command> [<args>]

Available commands are:
    down      Undo a database migration
    new       Create a new migration
    redo      Reapply the last migration
    status    Show migration status
    up        Migrates the database to the most recent version available
```

Each command requires a configuration file (which defaults to `dbconfig.yml`, but can be specified with the `-config` flag). This config file should specify one or more environments:

```yml
development:
  dialect: sqlite3
  datasource: test.db
  dir: migrations/sqlite3

production:
  dialect: postgres
  datasource: dbname=myapp sslmode=disable
  dir: migrations/postgres
  table: migrations
```

(See more examples for different set ups [here](test-integration/dbconfig.yml))

Also one can obtain env variables in datasource field via `os.ExpandEnv` embedded call for the field.
This may be useful if one doesn't want to store credentials in file:

```yml
production:
  dialect: postgres
  datasource: host=prodhost dbname=proddb user=${DB_USER} password=${DB_PASSWORD} sslmode=require
  dir: migrations
  table: migrations
```

The `table` setting is optional and will default to `gorp_migrations`.

The environment that will be used can be specified with the `-env` flag (defaults to `development`).

Use the `--help` flag in combination with any of the commands to get an overview of its usage:

```
$ sql-migrate up --help
Usage: sql-migrate up [options] ...

  Migrates the database to the most recent version available.

Options:

  -config=dbconfig.yml   Configuration file to use.
  -env="development"     Environment.
  -limit=0               Limit the number of migrations (0 = unlimited).
  -version               Run migrate up to a specific version, eg: the version number of migration 1_initial.sql is 1.
  -dryrun                Don't apply migrations, just print them.
```

The `new` command creates a new empty migration template using the following pattern `<current time>-<name>.sql`.

The `up` command applies all available migrations. By contrast, `down` will only apply one migration by default. This behavior can be changed for both by using the `-limit` parameter, and the `-version` parameter. Note `-version` has higher priority than `-limit` if you try to use them both.

The `redo` command will unapply the last migration and reapply it. This is useful during development, when you're writing migrations.

Use the `status` command to see the state of the applied migrations:

```bash
$ sql-migrate status
+---------------+-----------------------------------------+
|   MIGRATION   |                 APPLIED                 |
+---------------+-----------------------------------------+
| 1_initial.sql | 2014-09-13 08:19:06.788354925 +0000 UTC |
| 2_record.sql  | no                                      |
+---------------+-----------------------------------------+
```

#### Running Test Integrations

You can see how to run setups for different setups by executing the `.sh` files in [test-integration](test-integration/)

```bash
# Run mysql-env.sh example (you need to be in the project root directory)

./test-integration/mysql-env.sh
```

### MySQL Caveat

If you are using MySQL, you must append `?parseTime=true` to the `datasource` configuration. For example:

```yml
production:
  dialect: mysql
  datasource: root@/dbname?parseTime=true
  dir: migrations/mysql
  table: migrations
```

See [here](https://github.com/go-sql-driver/mysql#parsetime) for more information.

### Oracle (oci8)

Oracle Driver is [oci8](https://github.com/mattn/go-oci8), it is not pure Go code and relies on Oracle Office Client ([Instant Client](https://www.oracle.com/database/technologies/instant-client/downloads.html)), more detailed information is in the [oci8 repo](https://github.com/mattn/go-oci8).

#### Install with Oracle support

To install the library and command line program, use the following:

```bash
go get -tags oracle -v github.com/rubenv/sql-migrate/...
```

```yml
development:
  dialect: oci8
  datasource: user/password@localhost:1521/sid
  dir: migrations/oracle
  table: migrations
```

### Oracle (godror)

Oracle Driver is [godror](https://github.com/godror/godror), it is not pure Go code and relies on Oracle Office Client ([Instant Client](https://www.oracle.com/database/technologies/instant-client/downloads.html)), more detailed information is in the [godror repository](https://github.com/godror/godror).

#### Install with Oracle support

To install the library and command line program, use the following:

1. Install sql-migrate

```bash
go get -tags godror -v github.com/rubenv/sql-migrate/...
```

2. Download Oracle Office Client(e.g. macos, click [Instant Client](https://www.oracle.com/database/technologies/instant-client/downloads.html) if you are other system)

```bash
wget https://download.oracle.com/otn_software/mac/instantclient/193000/instantclient-basic-macos.x64-19.3.0.0.0dbru.zip
```

3. Configure environment variables `LD_LIBRARY_PATH`

```
export LD_LIBRARY_PATH=your_oracle_office_path/instantclient_19_3
```

```yml
development:
  dialect: godror
  datasource: user/password@localhost:1521/sid
  dir: migrations/oracle
  table: migrations
```

### As a library

Import sql-migrate into your application:

```go
import "github.com/rubenv/sql-migrate"
```

Set up a source of migrations, this can be from memory, from a set of files, from bindata (more on that later), or from any library that implements [`http.FileSystem`](https://godoc.org/net/http#FileSystem):

```go
// Hardcoded strings in memory:
migrations := &migrate.MemoryMigrationSource{
    Migrations: []*migrate.Migration{
        &migrate.Migration{
            Id:   "123",
            Up:   []string{"CREATE TABLE people (id int)"},
            Down: []string{"DROP TABLE people"},
        },
    },
}

// OR: Read migrations from a folder:
migrations := &migrate.FileMigrationSource{
    Dir: "db/migrations",
}

// OR: Use migrations from a packr box
// Note: Packr is no longer supported, your best option these days is [embed](https://pkg.go.dev/embed)
migrations := &migrate.PackrMigrationSource{
    Box: packr.New("migrations", "./migrations"),
}

// OR: Use pkger which implements `http.FileSystem`
migrationSource := &migrate.HttpFileSystemMigrationSource{
    FileSystem: pkger.Dir("/db/migrations"),
}

// OR: Use migrations from bindata:
migrations := &migrate.AssetMigrationSource{
    Asset:    Asset,
    AssetDir: AssetDir,
    Dir:      "migrations",
}

// OR: Read migrations from a `http.FileSystem`
migrationSource := &migrate.HttpFileSystemMigrationSource{
    FileSystem: httpFS,
}
```

Then use the `Exec` function to upgrade your database:

```go
db, err := sql.Open("sqlite3", filename)
if err != nil {
    // Handle errors!
}

n, err := migrate.Exec(db, "sqlite3", migrations, migrate.Up)
if err != nil {
    // Handle errors!
}
fmt.Printf("Applied %d migrations!\n", n)
```

Note that `n` can be greater than `0` even if there is an error: any migration that succeeded will remain applied even if a later one fails.

Check [the GoDoc reference](https://godoc.org/github.com/rubenv/sql-migrate) for the full documentation.

## Writing migrations

Migrations are defined in SQL files, which contain a set of SQL statements. Special comments are used to distinguish up and down migrations.

```sql
-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE people (id int);


-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE people;
```

You can put multiple statements in each block, as long as you end them with a semicolon (`;`).

You can alternatively set up a separator string that matches an entire line by setting `sqlparse.LineSeparator`. This
can be used to imitate, for example, MS SQL Query Analyzer functionality where commands can be separated by a line with
contents of `GO`. If `sqlparse.LineSeparator` is matched, it will not be included in the resulting migration scripts.

If you have complex statements which contain semicolons, use `StatementBegin` and `StatementEnd` to indicate boundaries:

```sql
-- +migrate Up
CREATE TABLE people (id int);

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION do_something()
returns void AS $$
DECLARE
  create_query text;
BEGIN
  -- Do something here
END;
$$
language plpgsql;
-- +migrate StatementEnd

-- +migrate Down
DROP FUNCTION do_something();
DROP TABLE people;
```

The order in which migrations are applied is defined through the filename: sql-migrate will sort migrations based on their name. It's recommended to use an increasing version number or a timestamp as the first part of the filename.

Normally each migration is run within a transaction in order to guarantee that it is fully atomic. However some SQL commands (for example creating an index concurrently in PostgreSQL) cannot be executed inside a transaction. In order to execute such a command in a migration, the migration can be run using the `notransaction` option:

```sql
-- +migrate Up notransaction
CREATE UNIQUE INDEX CONCURRENTLY people_unique_id_idx ON people (id);

-- +migrate Down
DROP INDEX people_unique_id_idx;
```

## Embedding migrations with [embed](https://pkg.go.dev/embed)

If you like your Go applications self-contained (that is: a single binary): use [embed](https://pkg.go.dev/embed) to embed the migration files.

Just write your migration files as usual, as a set of SQL files in a folder.

Import the embed package into your application and point it to your migrations:

```go
import "embed"

//go:embed migrations/*
var dbMigrations embed.FS
```

Use the `EmbedFileSystemMigrationSource` in your application to find the migrations:

```go
migrations := migrate.EmbedFileSystemMigrationSource{
	FileSystem: dbMigrations,
	Root:       "migrations",
}
```

Other options such as [packr](https://github.com/gobuffalo/packr) or [go-bindata](https://github.com/shuLhan/go-bindata) are no longer recommended.

## Embedding migrations with libraries that implement `http.FileSystem`

You can also embed migrations with any library that implements `http.FileSystem`, like [`vfsgen`](https://github.com/shurcooL/vfsgen), [`parcello`](https://github.com/phogolabs/parcello), or [`go-resources`](https://github.com/omeid/go-resources).

```go
migrationSource := &migrate.HttpFileSystemMigrationSource{
    FileSystem: httpFS,
}
```

## Extending

Adding a new migration source means implementing `MigrationSource`.

```go
type MigrationSource interface {
    FindMigrations() ([]*Migration, error)
}
```

The resulting slice of migrations will be executed in the given order, so it should usually be sorted by the `Id` field.

## Usage with [sqlx](https://jmoiron.github.io/sqlx/)

This library is compatible with sqlx. When calling migrate just dereference the DB from your `*sqlx.DB`:

```
n, err := migrate.Exec(db.DB, "sqlite3", migrations, migrate.Up)
                    //   ^^^ <-- Here db is a *sqlx.DB, the db.DB field is the plain sql.DB
if err != nil {
    // Handle errors!
}
```

## Questions or Feedback?

You can use Github Issues for feedback or questions.

## License

This library is distributed under the [MIT](LICENSE) license.
