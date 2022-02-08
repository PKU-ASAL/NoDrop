// #include <assert.h>
// #include <fcntl.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h> /* uintmax_t */
// #include <string.h>
// #include <sys/mman.h>
// #include <unistd.h> /* sysconf */
// #include <signal.h>

// #include <inttypes.h>
// #include <rte_eal.h>
// #include <rte_ether.h>
// #include <rte_ethdev.h>
// #include <rte_cycles.h>
// #include <rte_lcore.h>
// #include <rte_mbuf.h>
// #include <rte_malloc.h>

// #define NUM_MBUFS 1023
// #define RX_RING_SIZE 512
// #define TX_RING_SIZE 512
// #define MBUF_CACHE_SIZE 250

// #define SERVER_PORT 0

// uint32_t total_logs = 0;
// struct rte_mempool *mbuf_pool;

// #ifndef CLIENT
// #include "common.h"
// #define MAX_RETRY_NUMBER 1000
// struct syslog_packet {
//     uint16_t magic;
//     char data[MAX_LOG_LENGTH];
// } __attribute__((packed));

// #ifndef SERVER
// void *__dso_handle = 0;
// extern int first_come_in;
// extern struct logmsg_block *__m_log;
// static struct rte_ether_hdr pkt_eth_hdr = {
//     .dst_addr = {0x00, 0x0c, 0x29, 0x73, 0xae, 0xca}
// };
// #endif //SERVER

// #endif // CLIENT

// /* Display the port MAC address. */
// static void
// show_MAC_address(uint16_t port) {
// 	struct rte_ether_addr addr;
// 	int retval = rte_eth_macaddr_get(port, &addr);
// 	if (retval != 0) {
//         printf("Cannot get port %u MAC\n", port);
// 		return;
//     }

// 	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
// 			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
// 			port,
// 			addr.addr_bytes[0], addr.addr_bytes[1],
// 			addr.addr_bytes[2], addr.addr_bytes[3],
// 			addr.addr_bytes[4], addr.addr_bytes[5]);
// }

// /*
//  * Initializes a given port using global settings and with the RX buffers
//  * coming from the mbuf_pool passed as a parameter.
//  */
// static inline int
// port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
//     int retval;
//     uint16_t q;
//     uint16_t nb_rxd = RX_RING_SIZE;
//     uint16_t nb_txd = TX_RING_SIZE;
//     const uint16_t rx_rings = 1, tx_rings = 1;
//     struct rte_eth_dev_info dev_info;
//     struct rte_eth_conf port_conf;
//     struct rte_eth_txconf txconf;
//     struct rte_eth_rxconf rxconf;

//     if (!rte_eth_dev_is_valid_port(port)) {
//         printf("Not a valid port: %d\n", port);
//         return -1;
//     }

//     memset(&port_conf, 0, sizeof(struct rte_eth_conf));

//     retval = rte_eth_dev_info_get(port, &dev_info);
//     if (retval != 0) {
//         printf("Error during getting device (port %u) info: %s\n",
//                 port, strerror(-retval));
//         return retval;
//     }

//     if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
//         port_conf.txmode.offloads |=
//             DEV_TX_OFFLOAD_MBUF_FAST_FREE;

//     /* Configure the Ethernet device. */
//     retval = rte_eth_dev_configure(port, 1, 1, &port_conf);
//     if (retval != 0) {
//         printf("Error during configuring device (port %u) info: %s\n",
//                 port, strerror(-retval));   
//         return retval;
//     }

//     retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
//     if (retval != 0) {
//         printf("Error during adjusting device (port %u) info: %s\n",
//                 port, strerror(-retval));   
//         return retval;
//     }

//     rxconf = dev_info.default_rxconf;
//     rxconf.offloads = port_conf.rxmode.offloads;
//     /* Allocate and set up 1 RX queue per Ethernet port. */
// 	for (q = 0; q < rx_rings; q++) {
// 		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
// 				rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
// 		if (retval < 0)
// 			return retval;
// 	}

//     txconf = dev_info.default_txconf;
//     txconf.offloads = port_conf.txmode.offloads;
//     /* Allocate and set up 1 TX queue per Ethernet port. */
//     for (q = 0; q < tx_rings; q++) {
//         retval = rte_eth_tx_queue_setup(port, q, nb_txd,
//                 rte_eth_dev_socket_id(port), &txconf);
//         if (retval < 0) {
//             printf("Error during setup tx_queue %u (port %u) info: %s\n",
//                     q, port, strerror(-retval));   
//             return retval;
//         }
//     }

//     /* Start the Ethernet port. */
//     retval = rte_eth_dev_start(port);
//     if (retval < 0) {
//         printf("Error during start port %u info: %s\n", 
//                 port, strerror(-retval));
//         return retval;
//     }

//     /* Display the port MAC address. */
//     show_MAC_address(port);

//     // /* Enable RX in promiscuous mode for the Ethernet device. */
//     // retval = rte_eth_promiscuous_enable(port);
//     // if (retval < 0) {
//     //     printf("Error during enable promiscuous (port %u) info: %s\n", 
//     //             port, strerror(-retval));
//     //     return retval;
//     // }

//     return 0;
// }

// #if defined(CLIENT) || defined(SERVER)
// static void
// signal_handler(int signal) {
//     rte_eth_dev_stop(SERVER_PORT);
//     rte_eth_dev_close(SERVER_PORT);
//     printf("client exiting...");
//     exit(0);
// }
// #else
// void handle_exit(void) { rte_eal_cleanup(); }
// #endif

// static void
// lcore_main(void) {
// #if defined(CLIENT)
//     while(1);
// #else
//     int i = 0;
//     struct rte_mbuf *mbufs[MAX_LOG_NR];
//     struct rte_ether_hdr *eth;
//     struct syslog_packet *p;

// #if defined(SERVER)
//     /* Run until the application is quit or killed. */
// 	int epoch = 0;
//     for(;;) {
//         /* Get burst of RX packets, from first port of pair. */
//         const uint16_t nb_rx = rte_eth_rx_burst(SERVER_PORT, 0, mbufs, MAX_LOG_NR);

//         if (unlikely(nb_rx == 0))
//             continue;

// 		int this_epoch_count = 0;
//         for (i = 0; i < nb_rx; ++i) {
//             eth = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
//             p = (struct syslog_packet *)&eth[1];
// 			if (p->magic == 0xAA55) {
// 				this_epoch_count++;
// 				printf("RX: %s\n", p->data);
// 			}
//             rte_pktmbuf_free(mbufs[i]);
//         }

// 		if (unlikely(this_epoch_count == 0))
// 			continue;

// 		epoch++;
// 		total_logs += this_epoch_count;
// 		printf("server: epoch=%d recv=%d\n  total_logs=%u\n", epoch, this_epoch_count, total_logs);
//     }
// #else
//     char *buf_ptr = __m_log->buf;
//     for(i = 0; i < __m_log->nr; i++) {
//         mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
//         if (mbufs[i] == NULL) {
//             printf("Cannot allocate mbuf on port %u\n", SERVER_PORT);
//             goto out;
//         }
    
//         eth = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
//         memcpy(eth, &pkt_eth_hdr, sizeof(pkt_eth_hdr));

//         p = (struct syslog_packet *)&eth[1];
//         p->magic = 0xAA55;
//         memcpy(p->data, buf_ptr, MAX_LOG_LENGTH);

//         mbufs[i]->pkt_len = mbufs[i]->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct syslog_packet);
//         buf_ptr += MAX_LOG_LENGTH;
//     }

//     uint16_t nb_done = 0;
//     uint16_t nb_retry = 0;
//     do {
//         nb_done += rte_eth_tx_burst(SERVER_PORT, 0, mbufs + nb_done, __m_log->nr - nb_done);
//         nb_retry++;
//     } while (nb_done < __m_log->nr && nb_retry < MAX_RETRY_NUMBER);
//     // const uint16_t nb_tx = rte_eth_tx_burst(SERVER_PORT, 0, mbufs, __m_log->nr);

//     printf("send: %d\n", nb_done);
//     total_logs += nb_done;

// out:
//     for (i = 0; i < __m_log->nr; i++)
//         rte_pktmbuf_free(mbufs[i]);
// #endif // SERVER

// #endif // CLIENT
// }

// int main(int argc, char **argv) {
// #if defined(CLIENT) || defined(SERVER)
//     signal(SIGINT, signal_handler);
//     /* Initialize the Environment Abstraction Layer (EAL). */
//     int ret = rte_eal_init(argc, argv);
//     if (ret < 0)
//         rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

//     argc -= ret;
//     argv += ret;

//     mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
//         MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

//     if (port_init(SERVER_PORT, mbuf_pool) != 0)
//         rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", SERVER_PORT);
// #else
//     if (first_come_in == 1) {
//         /* Initialize the Environment Abstraction Layer (EAL). */
//         int ret = rte_eal_init(argc, argv);
//         if (ret < 0) {
//             printf("Error with EAL initialization\n");
//             return EXIT_FAILURE;
//         }

//         argc -= ret;
//         argv += ret;

//         atexit(handle_exit);

//         mbuf_pool = rte_mempool_lookup("MBUF_POOL");

//         // tx_buffer = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_LOG_NR), 0, rte_eth_dev_socket_id(SERVER_PORT));
//         // if (tx_buffer == NULL) {
//         //     printf("Cannot allocate buffer for tx on port %u\n", SERVER_PORT);
//         //     return EXIT_FAILURE;
//         // }
//         // rte_eth_tx_buffer_init(tx_buffer, MAX_LOG_NR);
//     }
// #endif // CLIENT

//     if (mbuf_pool == NULL) {
//         printf("Cannot create mbuf pool\n");
//         return EXIT_FAILURE;
//     }

//     lcore_main();

//     return EXIT_SUCCESS;
// }

#include <stdio.h>
#include <unistd.h>

#include "common.h"

int count;
char path[10];

void on_exit() {
    FILE *file;
    if (!(file = fopen(path, "a"))) {
        file = stdin;
    }

    fprintf(file, "%d", count);
    fclose(file);
}

void on_init() {
    count = 0;
    sprintf(path, "%d.txt", getpid());
}

extern struct logmsg_block *__m_log;
int main(int argc, char *argv[], char *env[]) {
    int i;
    FILE *file;

    if(!(file = fopen(path, "a"))) {
        file = stdin;
    }

    count += __m_log->nr;
    for (i = 0; i < __m_log->nr; i++) {
        event_data_t *logp = &__m_log->log_buf[i];
        // fprintf(file, "%lu ", logp->id); //30,000 us = 30ms = 0.3 bms

        // fprintf(file, "%lu,%lu,%lu\n", logp->id, logp->timestamp.tv_sec, logp->timestamp.tv_usec);

        fprintf(file, "[%lu+%lu] (core %d) eid=%lu,pid=%d,nr=%lx,ret=%lx,rdi=%lx,rsi=%lx,rdx=%lx,r10=%lx,r8=%lx,r9=%lx\n", 
            logp->timestamp.tv_sec, logp->timestamp.tv_usec, logp->cpu, logp->id, logp->who,
            logp->reg.orig_rax, logp->reg.rax, logp->reg.rdi, logp->reg.rsi, logp->reg.rdx, logp->reg.r10, logp->reg.r8, logp->reg.r9);
    }

    fclose(file); 
    return 0;
}