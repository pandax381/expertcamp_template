#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "net.h"
#include "ether.h"

#define CLONE_DEVICE "/dev/net/tun"

struct ether_tap {
    char name[IFNAMSIZ];
    int fd;
    uint8_t addr[ETHER_ADDR_LEN];
};

#define PRIV(x) ((struct ether_tap *)x->priv)

static int
ether_tap_addr(struct net_device *dev) {
    int soc;
    struct ifreq ifr = {};

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s", strerror(errno));
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s", strerror(errno));
        close(soc);
        return -1;
    }
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int
ether_tap_open(struct net_device *dev)
{
    struct ether_tap *tap;
    struct ifreq ifr = {};

    tap = PRIV(dev);
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s", strerror(errno));
        return -1;
    }
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl [TUNSETIFF]: %s", strerror(errno));
        close(tap->fd);
        return -1;
    }
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        if (ether_tap_addr(dev) == -1) {
            errorf("ether_tap_addr() failure");
            close(tap->fd);
            return -1;
        }
    }
    return 0;
};

static int
ether_tap_close(struct net_device *dev)
{
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t
ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

int
ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t
ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s", strerror(errno));
        }
        return -1;
    }
    return len;
}

static int
ether_tap_poll(struct net_device *dev)
{
    struct pollfd pfd;
    int ret;

    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 0);
    switch (ret) {
    case -1:
        if (errno != EINTR) {
            errorf("poll: %s", strerror(errno));
        }
        /* fall through */
    case 0:
        return -1;
    }
    return ether_poll_helper(dev, ether_tap_read);
}

static struct net_device_ops ether_tap_ops = {
    /*
     * exercise: step10
     *   ネットワークデバイス固有の操作関数のアドレスを設定
     */
};

struct net_device *
ether_tap_init(const char *name, const char *addr)
{
    struct ether_tap *tap;
    struct net_device *dev;

    tap = calloc(1, sizeof(*tap));
    if (!tap) {
        errorf("calloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1;
    if (addr) {
        if (ether_addr_pton(addr, tap->addr) == -1) {
            errorf("invalid address, %s", addr);
            free(tap);
            return NULL;
        }
    }
    /*
     * exercise: step10
     *   (1) ネットワークデバイスのためのメモリをアロケートする
     *     - 初期化関数として ether_setup_helper を指定する
     *   (2) デバイス固有の操作関数郡を設定する
     *   (3) デバイス固有のプライベートな情報として tap のアドレスを格納する
     *   (4) ネットワークデバイスをプロトコルスタックに登録する
     */
    debugf("loopback device initialized, dev=%s", dev->name);
    return dev;
}
