#ifndef __CONFIG_H
#define __CONFIG_H

/* Debug configuration - define DEBUG to enable debug prints */
#define DEBUG 1

#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif

/* Packet size limits */
#define MAX_PKT_SIZE 1514
#define FRAG_BUFF_MAX_SIZE 300
#define MAX_PADDING_UNITS 20

/* Probability thresholds (0-100) */
#define PROBABILITY_OF_FRAGMENTATION 70
#define PROBABILITY_OF_PADDING 70
#define PROBABILITY_OF_DUMMY 70

#endif // __CONFIG_H
