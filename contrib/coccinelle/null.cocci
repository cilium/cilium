// spatch --sp-file null.cocci lib/*.h *.c *.h
//
// This script finds undefined behavior in BPF C code which LLVM
// does not warn about but optimizes instead. See GH PR #4881.

@r exists@
expression E;
identifier f;
position p;
@@

if (E == NULL)
{
  ... when != E = ...
  E@p->f
  ...
}

@script:python@
E << r.E;
p << r.p;
@@

print("* file: %s deref of NULL value %s on line %s" % (p[0].file,E,p[0].line))
