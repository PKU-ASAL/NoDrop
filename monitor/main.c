#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* uintmax_t */
#include <string.h>
#include <sys/mman.h>
#include <unistd.h> /* sysconf */
#include <signal.h>

#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>

#ifndef PRIMARY
#include "common.h"
#endif // PRIMARY


/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

#define NUM_MBUFS 1023
#define MBUF_CACHE_SIZE 250

#define SERVER_PORT 0
#define BUFFER_SIZE 128
#define NUM_LOGS 32

uint32_t total_logs;

#ifndef PRIMARY
void *__dso_handle = 0;
extern int first_come_in;
extern struct logmsg_block *__m_log;
struct syslog_packet {
    char data[MAX_LOG_LENGTH];
    uint16_t magic;
};
#endif // PRIMARY

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

static void
show_MAC_address(uint16_t port) {
    /* Display the port MAC address. */
	struct rte_ether_addr addr;
	int retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0) {
        printf("Cannot get port %u MAC\n", port);
		return;
    }

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 0, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) {
        printf("Not a valid port: %d\n", port);
        return -1;
    }

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        printf("Error during configuring device (port %u) info: %s\n",
                port, strerror(-retval));   
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        printf("Error during adjusting device (port %u) info: %s\n",
                port, strerror(-retval));   
        return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) {
            printf("Error during setup tx_queue %u (port %u) info: %s\n",
                    q, port, strerror(-retval));   
            return retval;
        }
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        printf("Error during start port %u info: %s\n", 
                port, strerror(-retval));
        return retval;
    }

    /* Display the port MAC address. */
    show_MAC_address(port);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval < 0) {
        printf("Error during enable promiscuous (port %u) info: %s\n", 
                port, strerror(-retval));
        return retval;
    }

    return 0;
}

#ifdef PRIMARY
static void
signal_handler(int signal) {
    rte_eth_dev_stop(SERVER_PORT);
    rte_eth_dev_close(SERVER_PORT);
    printf("client exiting...");
    exit(0);
}

static void
lcore_main(struct rte_mempool *mbuf_pool) {
    printf("looping...\n");
    while(1);
// struct syslog_packet {
//     char data[128];
//     uint16_t magic;
// } *p;
//     struct rte_mbuf *mbuf;

//     mbuf = rte_pktmbuf_alloc(mbuf_pool);
//     p = rte_pktmbuf_mtod(mbuf, struct syslog_packet *);
//     p->magic = 0xAA55;

//     memcpy(p->data, "hello, world!", 128);

//     mbuf->data_len = sizeof(struct syslog_packet);
//     mbuf->pkt_len = sizeof(struct syslog_packet);

//     rte_eth_tx_burst(SERVER_PORT, 0, mbuf, 1);
}
#else
void handle_exit(void) { rte_eal_cleanup(); }

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_main(struct rte_mempool *mbuf_pool) {
    int i = 0;
    struct rte_mbuf *mbufs[MAX_LOG_NR];
    struct syslog_packet *p;
    char *buf_ptr = __m_log->buf;

    for(i = 0; i < __m_log->nr; i++) {
        mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
        if (mbufs[i] == NULL)
            rte_exit(EXIT_FAILURE, "Can not alloc mbuf");
    
        p = rte_pktmbuf_mtod(mbufs[i], struct syslog_packet *);
        p->magic = 0xAA55;

        memcpy(p->data, buf_ptr, MAX_LOG_LENGTH);
        buf_ptr += MAX_LOG_LENGTH;

        mbufs[i]->data_len = sizeof(struct syslog_packet);
        mbufs[i]->pkt_len = sizeof(struct syslog_packet);
    }
    /* Send burst of TX packets, to second port of pair. */
    const uint16_t nb_tx = rte_eth_tx_burst(SERVER_PORT, 0, mbufs, __m_log->nr);

    // struct rte_eth_stats stat;
    // rte_eth_stats_get(SERVER_PORT, &stat);
    // printf("ipackets=%d\topackets=%d\nibytes=%d\tobytes=%d\nierrors=%d\toerrors=%d\n", 
    // 		stat.ipackets, stat.opackets, stat.ibytes, stat.obytes, stat.ierrors, stat.oerrors);

    total_logs +=  nb_tx;

    /* Free any unsent packets. */
    if (unlikely(nb_tx < __m_log->nr)) {
        uint16_t buf;
        for (buf = nb_tx; buf < __m_log->nr; buf++)
            rte_pktmbuf_free(mbufs[buf]);
    }
}
#endif //PRIMARY

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

#ifdef PRIMARY
    signal(SIGINT, signal_handler);
#else
    if (!first_come_in)
        goto after_init;
    
    atexit(handle_exit);
#endif // PRIMARY

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

after_init:
    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "Error: no available ports\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    } else {
        mbuf_pool = rte_mempool_lookup("MBUF_POOL");
    }

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (port_init(SERVER_PORT, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					SERVER_PORT);
        show_MAC_address(SERVER_PORT);
	}

    /* Call lcore_main on the main core only. */
    lcore_main(mbuf_pool);

    return EXIT_SUCCESS;
}
