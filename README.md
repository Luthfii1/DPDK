DPDK is a set of libraries and drivers for fast packet processing.
It supports many processor architectures and both FreeBSD and Linux.

The DPDK uses the Open Source BSD-3-Clause license for the core libraries
and drivers. The kernel components are GPL-2.0 licensed.

Please check the doc directory for release notes,
API documentation, and sample application information.

For questions and usage discussions, subscribe to: users@dpdk.org
Report bugs and issues to the development mailing list: dev@dpdk.org

# DU-UP Usage #

1. Enter DU-UP directory
```shell
$ cd examples/du_up_per_flow
```

2. Build DU-UP
```shell
$ make clean && make
```

3. Run DU-UP Example
```shell
$ cd build/
$ sudo ./du_up -l 0-6 -n 4 -- -p 0xf --cfg-file ../profile.cfg
```

## Example Explanation ##
* EAL parameters
    - `-l`: lcore indices
    - `-n`: number of memory channel
* DU-UP App parameters
    - `-p`: port mask
    - `cfg-file`: DU-UP App config file

## Document for DU-UP App Config File ##

### Example ###
```conf
; lcore configuration
[lcore 1]
role = ue
port = 0

[lcore 2]
role = ue
port = 1

[lcore 3]
role = ue
port = 2

[lcore 4]
role = cu_tx ; Trasmit packets from UE port to CU port
port = 0 1 2 ; list of UE port (mapping to ring buffer index)

[lcore 5]
role = cu_rx ; Receive packets from CU port
port = 3 ; CU port

[lcore 6]
role = kni
port = 0 1 2 3

; UP configuration
[DU_UP]
dl trunk ip = 172.19.0.5
f1u ip = 172.20.0.5
```

### Lcore Configuration ###
* role
    - ue: Receive packets from UE port
    - cu_tx: Transmit packets to CU port
    - cu_rx: Receive packets from CU port and Transmit packets to UE port
    - kni: Receive packets from KNI devices and Transmit packets to UE/CU port
* port:
    - ue: UE port
    - cu_tx: all UE ports
    - cu_rx: CU port
    - kni: all UE ports and CU port

### DU-UP Configuration ###
* dl trunk ip: DU Trunk IP
* f1u ip: DU-UP F1-U IP