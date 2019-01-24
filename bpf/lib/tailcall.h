#ifndef TAILCALL_H
#define TAILCALL_H

#define __eval(x, ...) x ## __VA_ARGS__

#define __and_00 0
#define __and_01 0
#define __and_10 0
#define __and_11 1
#define __and_0(y)  __eval(__and_0, y)
#define __and_1(y)  __eval(__and_1, y)
#define __and(x, y) __eval(__and_, x)(y)

#define __or_00 0
#define __or_01 1
#define __or_10 1
#define __or_11 1
#define __or_0(y)  __eval(__or_0, y)
#define __or_1(y)  __eval(__or_1, y)
#define __or(x, y) __eval(__or_, x)(y)

#define __declare_tailcall_if_0(NAME)         \
	static __always_inline
#define __declare_tailcall_if_1(NAME)         \
	__section_tail(CILIUM_MAP_CALLS, NAME)
#define declare_tailcall_if(COND, NAME)       \
	__eval(__declare_tailcall_if_, COND)(NAME)

#define __invoke_tailcall_if_0(NAME, FUNC)    \
	return FUNC(skb)
#define __invoke_tailcall_if_1(NAME, FUNC)    \
	do {                                  \
		ep_tail_call(skb, NAME);      \
		ret = DROP_MISSED_TAIL_CALL;  \
	} while (0)
#define invoke_tailcall_if(COND, NAME, FUNC)  \
	__eval(__invoke_tailcall_if_, COND)(NAME, FUNC)

#endif /* TAILCALL_H */
