[![Build Status](https://travis-ci.org/k-sone/critbitgo.svg?branch=master)](https://travis-ci.org/k-sone/critbitgo)

critbitgo
=========

[Crit-bit trees](http://cr.yp.to/critbit.html) in golang and its applications.

This implementation extended to handle the key that contains a null character from [C implementation](https://github.com/agl/critbit).

Usage
--------

```go
// Create Trie
trie := critbitgo.NewTrie()

// Insert
trie.Insert([]byte("aa"), "value1")
trie.Insert([]byte("bb"), "value2")
trie.Insert([]byte("ab"), "value3")

// Get
v, ok := trie.Get([]byte("aa"))
fmt.Println(v, ok)    // -> value1 true

// Iterate containing keys
trie.Allprefixed([]byte{}, func(key []byte, value interface{}) bool {
    fmt.Println(key, value) // -> [97 97] value1
                            //    [97 98] value3
                            //    [98 98] value2
    return true
})

// Delete
v, ok = trie.Delete([]byte("aa"))
fmt.Println(v, ok)    // -> value1 true
v, ok = trie.Delete([]byte("aa"))
fmt.Println(v, ok)    // -> <nil> false
```

License
-------

MIT
