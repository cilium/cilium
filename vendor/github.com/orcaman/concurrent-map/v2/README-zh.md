# concurrent map [![Build Status](https://travis-ci.com/orcaman/concurrent-map.svg?branch=master)](https://travis-ci.com/orcaman/concurrent-map)

正如 [这里](http://golang.org/doc/faq#atomic_maps) 和 [这里](http://blog.golang.org/go-maps-in-action)所描述的, Go语言原生的`map`类型并不支持并发读写。`concurrent-map`提供了一种高性能的解决方案:通过对内部`map`进行分片，降低锁粒度，从而达到最少的锁等待时间(锁冲突)

在Go 1.9之前，go语言标准库中并没有实现并发`map`。在Go 1.9中，引入了`sync.Map`。新的`sync.Map`与此`concurrent-map`有几个关键区别。标准库中的`sync.Map`是专为`append-only`场景设计的。因此，如果您想将`Map`用于一个类似内存数据库，那么使用我们的版本可能会受益。你可以在golang repo上读到更多，[这里](https://github.com/golang/go/issues/21035) and [这里](https://stackoverflow.com/questions/11063473/map-with-concurrent-access)
***译注:`sync.Map`在读多写少性能比较好，否则并发性能很差***

## 用法

导入包:

```go
import (
	"github.com/orcaman/concurrent-map/v2"
)

```

```bash
go get "github.com/orcaman/concurrent-map/v2"
```

现在包被导入到了`cmap`命名空间下
***译注:通常包的限定前缀(命名空间)是和目录名一致的，但是这个包有点典型😂，不一致！！！所以用的时候注意***

## 示例

```go

	// 创建一个新的 map.
	m := cmap.New[string]()

	// 设置变量m一个键为“foo”值为“bar”键值对
	m.Set("foo", "bar")

	// 从m中获取指定键值.
	bar, ok := m.Get("foo")

	// 删除键为“foo”的项
	m.Remove("foo")

```

更多使用示例请查看`concurrent_map_test.go`.

运行测试:

```bash
go test "github.com/orcaman/concurrent-map/v2"
```

## 贡献说明

我们非常欢迎大家的贡献。如欲合并贡献，请遵循以下指引:
- 新建一个issue,并且叙述为什么这么做(解决一个bug，增加一个功能，等等)
- 根据核心团队对上述问题的反馈，提交一个PR，描述变更并链接到该问题。
- 新代码必须具有测试覆盖率。
- 如果代码是关于性能问题的，则必须在流程中包括基准测试(无论是在问题中还是在PR中)。
- 一般来说，我们希望`concurrent-map`尽可能简单，且与原生的`map`有相似的操作。当你新建issue时请注意这一点。

## 许可证
MIT (see [LICENSE](https://github.com/orcaman/concurrent-map/blob/master/LICENSE) file)
