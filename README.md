# ppc-crawler

Crawl directories with supportconfigs for ppc64le cases, and collect some hardware aspects in order to recognize some regular appearing issues.

## Description

We see a couple of common PPC64LE failure patterns, that deserve further investigation. 

- network thoughput limitation
- soft lock-ups 
- high cpu usage

The first is caused at least in part by a deficit of the `ibmveth` driver, that isn't able to distribute interrupts to multiple cpus properly.
The official solution of IBM is to create a bonding -alb device with up to 8 interfaces. 

The causes of the second and third ones are not completely understood. Typically, the `sys` load is raising including the `steal` percentage, 
and workqueues pile up. We want to examine, if kernel and firmware versions contribute to the problem.

Run the program by supplying a directory containing one or more supportconfigs. It will search for `hardware.txt` files, and make sure, that
the architecture is `ppc64le`. Then it also parses the `basic-environment.txt`.

At that time, it just produces a condenced output similar to:
```
PPC(
     path: '.../SFSC00303987/scc_labbhn1_210903_0902'
     date: 'Fri Sep  3 09:03:12 CEST 2021'
 hostname: 'labbhn1'
   kernel: '4.12.14-150.72-default'
   os_ver: 'SLES 15'
cpu_count: 16
 cpu_type: {'POWER9 (architected), altivec supported'}
    model: 'IBM,9080-M9S'
  machine: 'CHRP IBM,9080-M9S'
 platform: 'pSeries'
      irq: {19: IRQ(nr=19, count=16966701, name='eth0', dist=10.9),
            20: IRQ(nr=20, count=33817, name='eth1', dist=9.2)}
      nic: {'eth0': NIC(model='IBM Virtual Ethernet card 1', driver='ibmveth', device='eth0', hwaddr='22:9f:89:ce:b0:02', hwaddrp='22:9f:89:ce:b0:02', link=True),
            'eth1': NIC(model='IBM Virtual Ethernet card 0', driver='ibmveth', device='eth1', hwaddr='22:9f:89:ce:b0:03', hwaddrp='22:9f:89:ce:b0:03', link=True)}
   fw_lvl: 'FW930.30 FW930.03 FW930.30'
   fw_dat: '20201007 20190809 20201007'
   fw_img: 'VH930_116 VH930_068 VH930_116'
)

```

This is a *good* one already. Note the dist value of the interrupts. This value is made up from these interrupts:

```
irq: 19: [15120028, 0, 0, 0, 0, 0, 0, 0, 1846673, 0, 0, 0, 0, 0, 0, 0]
irq: 20: [30713, 0, 0, 0, 0, 0, 0, 0, 3104, 0, 0, 0, 0, 0, 0, 0]
```

It is a number between 0 and 100 to reflect the distribution of this interrupt over all CPUs.

The algorithm works as follows:

If the number of interrupts per CPU is between 0 and twice the average of all interrupts per CPU, let this be included in the total distribution.
In this example for IRQ 19: total number of interrupts: 16966701, average number per CPU: 1060419.
15120028 is 14 times the average value and is discarded, 1846673 is 1.7 times, and is thus taken into account. 100/16 * 1.7 = 10.9.

## Usage

The minimum supported Python version is 3.6.

On `ziu.nue.suse.com`, you need to call this program by:
```
python3.6 ./ppc-crawler.py /srv/www/htdocs/SFSC<case-nr.>/
```

Specifying `-v` reveals some details, and another `-v` probably reveals more than you ever wanted to see.

