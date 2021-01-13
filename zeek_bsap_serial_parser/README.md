# BSAP Serial to Ethernet

## Overview

This is an BSAP Serial to Ethernet parser developed for the Zeek NSM platform. 

This parser requires that there is a Serial to Ethernet converter converting serial BSAP to Ethernet using ports 1234 or 1235 over UDP. 

This parser has been developed as a Zeek plugin that can be added to existing Zeek installations and log important fields and variables within the BSAP protocol. This parser was developed to be capture the most common used functions in the field. The functions within the [scripts/main.zeek](scripts/main.zeek) and [src/events.bif](src/events.bif) file should prove to be a good guide on how to add new logging functionality.

There are currently 4 Zeek log files that can be output by this parser. These log files are defined in the [scripts/main.zeek](scripts/main.zeek) file.
* bsap_serial_header.log
* bsap_serial_rdb.log
* bsap_serial_rdb_ext.log
* bsap_serial_unknown.log 

For additional information on these log files, see the *Logging Capabilities* section below.

## NOTE
If other BSAP parsers are installed ie. (BSAP_IP) then there will likely be other logs that show up because they will be parsing messages that come across on port 1234,1235 over UDP. If you would like to keep these separate you can change the ports on the serial to ethernet converter to a port that is not used. In (scripts/main.zeek) you can change the port to match the ports on the serial to ethernet converter before compiling code.

## Installation

```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_bsap_serial_parser/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see Zeek::BSAP_SERIAL
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see Zeek::BSAP_SERIAL
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the Zeek_Bsap_serial.tar.gz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Bsap_serial.tar.gz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### BSAP Header Log (bsap_serial_header.log)

#### Overview

This log captures BSAP header information for every BSAP packet converted to ethernet and logs it to **bsap_serial_header.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| ser               | string    | Message Serial Number                                     |
| dadd              | count     | Destination Address                                       |
| sadd              | count     | Source Address                                            |
| ctl               | count     | Control Byte                                              |
| dfun              | string    | Destination Function                                      |
| seq               | count     | Message Sequence                                          |
| sfun              | string    | Source Function                                           |
| nsb               | count     | Node Status Byte                                          |
| type_name         | string    | Local vs Global header                                    |

### BSAP RDB (Remote Database Access) Log (bsap_serial_rdb.log)

#### Overview

This log captures BSAP RDB function information and logs it to **bsap_serial_rdb.log**.

The vast majority of BSAP traffic is RDB function traffic. The RDB access is used to read and write 
variables between master and slave RTU's.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| func_code             | string    | RDB function being initiated                              |
| data                  | string    | RDB function specific data                                |


### BSAP BSAP_RDB_EXT (Remote Database Access Extended) Log (bsap_serial_rdb_ext.log)

#### Overview

This log captures BSAP RDB Extension function information and logs it to **bsap_serial_rdb_ext.log**.

These Extension functions of RDB contain information from controllers loading date and time setting
clearing diagnostics, and calling system resets. These only purtain to the GFC 3308 controllers.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| dfun                  | string    | Destination Function                                      |
| seq                   | count     | Message Sequence                                          |
| sfun                  | string    | Source Function                                           |
| nsb                   | count     | Node Status Byte                                          |
| extfun                | string    | RDB extension function                                    |
| data                  | string    | RDB Ext function specific data                            |



### BSAP Unknown (bsap_serial_unknown.log)

#### Overview

This log captures all other BSAP traffic that hasn't been defined and logs it to **bsap_serial_unknown.log**.


#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| data                  | string    | BSAP unknown data                                         |


## Testing

This script has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from combining various packet captures captured at Idaho National Laboratory.
