# Switcharoo-P4

<p align="right">
    <a href="https://doi.org/10.5281/zenodo.10184767"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.10184767.svg" alt="DOI"></a>
</p>

This repository contains the P4 implementation of Switcharoo for Intel Tofino. 
Switcharoo is a key-value data structure entirely implemented in the data plane that supports millions of modifications per second.

This implementation is tested with **SDE 9.8.0** and **SDE 9.9.1**.

## Project Structure

The main file is `switcharoo.p4`. It contains the implementation of the entire pipeline. 

The `cuckoo_pipe` directory contains the logic for the cuckoo-hash table pipeline. 

The `bloom_pipe` directory contains the logic for the ordering pipeline. 

The `include` directory contains general configuration files. 

The file `setup.py` contains a `bfrt_python` script that configures ports, mirroring, and other several callbacks for the program.

## How to Build

Example command to build the code, it can vary depending on your SDE installation: 
```bash 
./p4_build.sh switcharoo.p4
```
You can specify different compilation-time parameters:
- `ENTRY_TIMEOUT`: timeout of the entries in the cuckoo-hash table (in nanoseconds). Default is 50000.
- `MAX_LOOPS_WAIT`: number of recirculations before a WAIT packet is sent out. Default is 10.
- `MAX_LOOPS_INSERT`: number of recirculations of the same packet before the transient states of the corresponding flow are reset. Default is 20.
- `TABLE_SIZE`: number of entries in the cuckoo-hash table (minimum is 128, maximum is 65536). Default is 65536.
- `BLOOM_FILTER_SIZE`: number of entries in the Ordering and Flow Count bloom filters (minimum is 128, maximum is 65536). Default is 65536.
- `SWAP_BLOOM_FILTER_SIZE`: number of entries in the Swap and Swapped bloom filters (minimum is 128, maximum is 65536). Default is 65536.

For example, if you want to compile Switcharoo with a cuckoo-hash table of 32768 entries and an expiration timeout of 10us:
```bash
./p4_build.sh -DENTRY_TIMEOUT=10000 -DTABLE_SIZE=32768 switcharoo.p4
```

## How to Run

Example commands to run Switcharoo, they can vary depending on your SDE installation.
On a terminal, run `switchd`:
```bash 
$SDE/run_switchd.sh -p switcharoo
```
On another terminal, launch the `setup.py` script using `bfshell`:
```bash 
$SDE/run_bfshell.sh -i -b /absolute/path/to/setup.py
```

### Running Switcharoo on a 2-pipe Tofino switch
By default, P4 programs are compiled using a 4-pipes layout. Hence, if you are using a 2-pipe Tofino ASIC, the program will not be launched since the mapping will fail. 

In this repository, we provide a proper 2-pipes mapping file (`switcharoo.conf`) that has to be loaded when launching `run_switchd.sh`. The mapping assigns the `cuckoo` pipe to the first pipe of the ASIC and the `bloom` pipe to the second one.
You can change the mapping by changing the `pipe_scope` key in the `switcharoo.conf` file.

To run `switchd` with the new mapping, type the following command:
```bash 
$SDE/run_switchd.sh -p switcharoo -c /absolute/path/to/switcharoo.conf
```

## How to Configure Switcharoo

### Configure the Ports

<p align="center">
    <img src=img/port-config.png?raw=true" alt="Port Configuration" />
</p>

The figure shows the port configuration of Switcharoo.

You can find ports configuration in the `include/configuration.p4` file. Here you can set the output port and 
the recirculation ports. If you make changes, you need to update the ports value in the `setup.py` file accordingly. 

The outport ports specified in the files are used to send out the traffic after being processed by Switcharoo. 
The current implementation sends out the packets randomly assigning an IPv4 identification in the `cuckoo` pipe using the `select_flow_id` table. The identification is then used in the `bloom` pipe to send out the packet using the `forward` table, which is filled in the `setup.py` file:

```python3
#########################
##### FORWARD TABLE #####
#########################
# This function setups the entries in the forward table.
# You can add/edit/remove entries to choose where output the packets based on the IPv4 identification.
def setup_forward_table():
    global switcharoo_bloom_pipe, OUTPUT_PORT_1, OUTPUT_PORT_2, OUTPUT_PORT_3, OUTPUT_PORT_4

    forward_table = switcharoo_bloom_pipe.BloomIngress.forward
    forward_table.clear()

    forward_table.add_with_send(identification=0xFFFF, port_number=OUTPUT_PORT_1)
    forward_table.add_with_send(identification=0xEEEE, port_number=OUTPUT_PORT_2)
    forward_table.add_with_send(identification=0xDDDD, port_number=OUTPUT_PORT_3)
    forward_table.add_with_send(identification=0xCCCC, port_number=OUTPUT_PORT_4)
```

To add a port, you need to:
- Add it in the `include/configuration.p4` file;
- Add it in the `setup.py` file;
- Add an additional entry in the `select_flow_id` of the `cuckoo` pipe;
- Add an additional entry in the `setup_forward_table` in the `setup.py` file.

Each input port is then mapped to several recirculation ports, which are used to share packets between the `cuckoo` and `bloom` pipe.
For each input port, you need three ports in the `cuckoo` pipe:
1. `RECIRCULATE_PORT_INSERT_IP*_TO_BLOOM`
2. `RECIRCULATE_PORT_WAIT_IP*_TO_BLOOM`
3. `RECIRCULATE_PORT_NOP_IP*_TO_BLOOM`

And two ports in the `bloom` pipe:
1. `RECIRCULATE_PORT_INSERT_IP*_TO_CUCKOO`
2. `RECIRCULATE_PORT_LOOKUP_IP*_TO_CUCKOO`

To handle traffic from a new port, you need to:
- Define the new recirculation ports in the `include/configuration.p4` file;
- Define new actions in the `include/recirculation_action.p4` file;
- Add the corresponding entries in the `select_bloom_recirculation_port` in the `cuckoo` pipe (you can follow the pattern of the other entries);
- Add the corresponding entries in the `select_cuckoo_recirculation_port` in the `bloom` pipe (you can follow the pattern of the other entries).

### Change Mirror Port
Switcharoo leverages on a mirror port (with mirroring ID=100) to perform swapping. 

If you want to change the mirroring port, you have to:
- Change the `RECIRCULATE_PORT_SWAP_TO_CUCKOO` definition in the `setup.py` file;
- Change the `RECIRCULATE_PORT_SWAP_TO_CUCKOO` definition in the `include/configuration.p4` file.

Additional modifications (e.g., the mirroring ID) can be done by changing the `setup.py` file `setup_mirror_session_table` callback:
```python3
#################################
##### MIRROR SESSIONS TABLE #####
#################################
# In this section, we setup the mirror sessions of SWITCHAROO.
# There is only one session, that is used to truncate/send swap operations to the Cuckoo Pipe.
PKT_MIN_LENGTH = 100
SWAP_MIRROR_SESSION = 100


def setup_mirror_session_table():
    global bfrt, SWAP_MIRROR_SESSION, RECIRCULATE_PORT_SWAP_TO_CUCKOO, PKT_MIN_LENGTH

    mirror_cfg = bfrt.mirror.cfg

    mirror_cfg.entry_with_normal(
        sid=SWAP_MIRROR_SESSION,
        direction="BOTH",
        session_enable=True,
        ucast_egress_port=RECIRCULATE_PORT_SWAP_TO_CUCKOO,
        ucast_egress_port_valid=1,
        max_pkt_len=PKT_MIN_LENGTH,
        packet_color="GREEN"
    ).push()
```

And the `include/configuration.p4` file:
```p4
/* Mirror Configuration */
const MirrorType_t SWAP_MIRROR = 1;
const MirrorId_t SWAP_MIRROR_SESSION = 100;
```
