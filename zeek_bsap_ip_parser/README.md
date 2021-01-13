# zeek_bsap_ip 

## Overview

This is a BSAP over IP parser developed for the Zeek NSM platform. 

This parser has been developed as a Zeek plugin that can be added to existing Zeek installations and log important fields and variables within the BSAP protocol. This parser was developed to be capture the most common used functions in the field. The functions within the [scripts/main.zeek](scripts/main.zeek) and [src/events.bif](src/events.bif) file should prove to be a good guide on how to add new logging functionality.

There are currently 3 Zeek log files that can be output by this parser. These log files are defined in the [scripts/main.zeek](scripts/main.zeek) file.
* bsap_ip_header.log
* bsap_ip_rdb.log
* bsap_ip_unknown.log 

For additional information on these log files, see the *Logging Capabilities* section below.

## NOTE
This parser has been tested using a Maple Systems HMI to an Emerson Control Wave Micro PLC. 
The communication is zeek_bsap_ip using Emerson BSAP Free Tag names driver

## Installation

```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_bsap_ip_parser/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see Zeek::BSAP_IP
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see Zeek::BSAP_IP
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the Zeek_Bsap_ip.tar.gz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Bsap_ip.tar.gz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### Header Log (bsap_ip_header.log)

#### Overview

This log captures BSAP header information for every BSAP packet converted to ethernet and logs it to **bsap_ip_header.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| num_msg           | string    | Number of functions per message                           |
| type_name         | count     | Message Type                                              |


### RDB (Remote Database Access) Log (bsap_ip_rdb.log)

#### Overview

This log captures BSAP RDB function information and logs it to **bsap_ip_rdb.log**.

The vast majority of BSAP traffic is RDB function traffic. The RDB access is used to read and write 
variables between master and slave RTU's.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| header_size           | count     | Header length                                             |
| mes_seq               | count     | Message Sequence                                          |
| res_seq               | count     | Response Sequence                                         |
| data_len              | count     | Length of data                                            |
| sequence              | count     | Function Sequence (Same as Response)                      |
| app_func_code         | string    | Application function                                      |
| node_status           | count     | Node Status Byte                                          |
| func_code             | string    | Application sub function                                  |
| data                  | string    | Sub function specific data                                |


### Unknown Log (bsap_ip_unknown.log)

#### Overview

This log captures all other zeek_bsap_ip traffic that hasn't been defined and logs it to **bsap_ip_unknown.log**.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| data                  | string    | BSAP_IP unknown data                                      |


## Testing

This script has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from combining various packet captures captured at Idaho National Laboratory.
