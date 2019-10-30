#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H

#define FEAT_TCP	(1<<0)
#define FEAT_UDP	(1<<1)
#define FEAT_IPV6	(1<<2)
#define FEAT_IPV4	(1<<3)
#define FEAT_ETHERNET	(1<<4)
#define FEAT_ALL	(FEAT_TCP|FEAT_UDP|FEAT_IPV6|FEAT_IPV4|FEAT_ETHERNET)

#define SRC_MASK (1<<0)
#define DST_MASK (1<<1)
#define TCP_MASK (1<<2)
#define UDP_MASK (1<<3)

#endif
