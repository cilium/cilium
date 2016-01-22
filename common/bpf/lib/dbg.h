#ifndef __LIB_DBG__
#define __LIB_DBG__

#define DEBUG
#ifdef DEBUG
# define printk(fmt, ...)					\
		({						\
			char ____fmt[] = fmt;			\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})
#else
# define printk(fmt, ...)					\
		do { } while (0)
#endif

#endif /* __LIB_DBG__ */
