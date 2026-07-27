# package bart

# Node Types Comparison
 
 BART implements three different node types, each optimized for specific use cases:
 
## Memory Footprint (64-bit systems)
 
**Base Components:**
- `BitSet256`: `[4]uint64` = **32 bytes**
- `sparse.Array256[T]`: `BitSet256 + []T` = **56 bytes + n×sizeof(T)**
 
**Child Reference Sizing:**
- `childRef`: 8 bytes (pointer) or 16 bytes (interface value storage)
- The actual size depends on implementation: 8B for `*node` pointers, 16B for `interface{}` values

### BartNode[V] - Dynamic Sparse Node
 ```go
type BartNode[V any] struct {
    prefixes sparse.Array256[V]        // 56 + n×sizeof(V)  
    children sparse.Array256[childRef] // 56 + m×sizeof(childRef)
 }
 ```
**Memory Usage:** **112 bytes + n×sizeof(V) + m×sizeof(childRef)**
 
### LiteNode - Dynamic Sparse, prefixes Bitset-Only Node
 ```go
type LiteNode struct {
    prefixes bitset.BitSet256           // 32 bytes (presence only)
    children sparse.Array256[childRef]  // 56 + m×sizeof(childRef)
    pfxCount uint16                     // 2 bytes + padding
 }
 ```
**Memory Usage:** **96 bytes + m×sizeof(childRef)** (no value storage)

### FastNode[V] - Fixed Array Node
 ```go
type FastNode[V any] struct {
    prefixes struct {
        bitset.BitSet256
        items [256]*V
    }                                // 2,048 + 32 bytes BitSet256
    children struct {
        bitset.BitSet256
        items [256]*any              // pointer-to-interface for 8‑byte nils
    }                                // 2,048 + 32 bytes BitSet256
    pfxCount uint16
    cldCount uint16                  // + padding
 }
 ```
**Memory Usage:** **4,168 bytes** (fixed, regardless of occupancy)
 
## Real-World Example
**Scenario:** Node with 10 prefixes, 5 children
 
 | Node Type | Base | *Payload | +Children | Total | **Bytes/Prefix** ¹ |
 |-----------|------|----------|----------|-----------|------------------|
 | LiteNode | 96 | 0 | 5×16=80 | 176 bytes | **17** |
 | BartNode[int] | 112 | 10×8=80 | 5×16=80 | 272 bytes | **27** |
 | FastNode[int] | 4,168 | 0 | 0 | 4,168 bytes | **417** |
 
¹ Values assume childRef = 16 bytes and pointer to payload = 8 bytes

## Extended Memory Example with Path Compression

### Path-Compressed Child Types

**Note:** In realistic scenarios, the value type `V` is typically a **pointer to a
payload struct** (e.g., `*RouteInfo`, `*Metadata`).
The calculations below assume `V = 8 bytes` (pointer size on 64-bit systems).
The actual payload struct referenced by the pointer is **not included** in these per-node calculations.

**LiteNode:**
- **LeafNode**: `netip.Prefix` only = **32 bytes** (Value field unused)
- **FringeNode**: **0 bytes** payload (prefix implicit from position, Value field unused)

**BartNode[V] / FastNode[V]:** (assuming V is a pointer = 8 bytes)
- **LeafNode[V]**: `Value (8B) + Prefix (32B)` = **40 bytes**
- **FringeNode[V]**: `Value (8B)` = **8 bytes** (prefix implicit from position)

### Realistic Scenario: Mixed Child Types

**Setup:** Node with 10 prefixes + 5 child nodes + 5 LeafNodes + 5 FringeNodes

**Total prefix items:** 10 (in-node) + 5 (leaves) + 5 (fringes) = **20 prefix items**

| Node Type | Base | Prefixes¹ | Children² | Subtotal | + Leaves³ | + Fringes⁴ | **Bytes/Prefix**⁵ |
|-----------|------|-----------|-----------|----------|-----------|------------|-------------------|
| **LiteNode** | 96 B | 0 | 15×16=240 B | 336 B | +160 B | +0 B | **16.8** |
| **BartNode[V]** | 112 B | 10×8=80 B | 15×16=240 B | 432 B | +200 B | +40 B | **21.6** |
| **FastNode[V]** | 4,168 B | 0 | 0 | 4,168 B | +200 B | +40 B | **208.4** |

**Notes:**
1. Prefixes: LiteNode stores no values (0B); BartNode/FastNode store 10×8B pointers to payload structs
2. Children: 15 total (5 nodes + 5 leaves + 5 fringes), each as `interface{}` = 16 bytes
3. Leaves: LiteNode stores 5×32B LeafNode (unused Value field), BartNode/FastNode store
   5×40B LeafNode[V] (with 8B pointer each)
4. Fringes: LiteNode stores 0B (prefix implicit, unused Value field), BartNode/FastNode store
   5×8B FringeNode[V] (8B pointer)
5. Calculated as: `Subtotal / 20` (node itself only, excluding referenced child nodes and external
   payload structs)

### Memory Efficiency Insights

**LiteNode advantages:**
- **No value storage** in LeafNode: saves 8 bytes per leaf (32B vs 40B)
- **No value storage** in FringeNode: saves 8 bytes per fringe (0B vs 8B)
- **No in-node prefix values**: saves 80 bytes for 10 prefixes vs BartNode
- **Total savings:** ~22% smaller than BartNode for typical routing tables

**Path compression benefits:**
- **LeafNode**: Eliminates intermediate nodes for isolated prefixes
- **FringeNode**: Compresses /8, /16, /24 boundaries without node overhead
- **Reduced trie depth**: Fewer levels = fewer lookups per route

**Important:** The actual payload structs (e.g., routing information, metadata) are stored externally and referenced by the 8-byte pointers. Their sizes are not included in the per-node calculations above, as they are shared or application-specific.
 
## Lookup Performance Deep Dive
 
 All three node types achieve **O(1) per-level lookup performance**, but must traverse trie levels:
 
### Trie Structure & Performance
- **8-bit strides per level**: Each trie level handles 8 bits of the IP address
- **IPv4 traversal**: Worst case  4 levels (32÷8),  real-world typically 3 levels for /24 routes
- **IPv6 traversal**: Worst case 16 levels (128÷8), real-world typically 6 levels for /48 routes
- **Performance characteristic**: O(trie_depth) not O(number_of_routes)
- **IPv6 vs IPv4**: IPv6 inherently ~2× slower due to deeper tree structure
 
### BartNode[V] & LiteNode - Optimized Level Operations
- **Precomputed lookup tables** (`lpm.LookupTbl[idx]`) eliminate search within each level
- **BitSet256 intersections** via `IntersectionTop()` for instant prefix matching
- **Rank-based indirection**: Bitset-to-slice mapping uses precomputed Rank masks
- **Pipeline-friendly**: Only 4 bitset operations (4×uint64) per level, optimized for CPU pipelining
- **No backtracking**: Traditional longest-prefix-match backtracking replaced with direct table lookups
 
### FastNode[V] - Direct Array Access per Level
- **Zero indirection per level**: Direct array indexing `prefixes[idx]` and `children[idx]`
- **Cache-optimal**: Contiguous memory layout within each level
- **Performance advantage**: Still ~40% faster per level despite sparse optimizations
