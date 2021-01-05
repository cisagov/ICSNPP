# BACnet Zeek Parser Plugin

## Overview

This is a BACnet parser developed for the Zeek NSM platform. 

This parser has been developed as a Zeek plugin that can be added to existing Zeek installations and log important fields and variables within the BACnet protocol. This parser was developed to be fully customizable, so if you would like to drill down into specific BACnet packets and log certain variables, all you need to do is add the logging functionality to the scripts/main.zeek file. The functions within the [scripts/main.zeek](scripts/main.zeek) and [src/events.bif](src/events.bif) file should prove to be a good guide on how to add new logging functionality.

There are currently 3 Zeek log files that can be output by this parser. These log files are defined in the [scripts/main.zeek](scripts/main.zeek) file.
* bacnet.log
* bacnet_discovery.log
* bacnet_property.log. 

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_bacnet_parser/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see Zeek::BACnet
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see Zeek::BACnet
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the Zeek_Bacnet.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Bacnet.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### BACnet Header Log (bacnet.log)

#### Overview

This log captures BACnet header information for every BACnet/IP packet and logs them to **bacnet.log**.

#### Fields Captured

| Field         | Type      | Description                                               |
| ------------- |-----------|-----------------------------------------------------------| 
| ts            | time      | Timestamp                                                 |
| uid           | string    | Unique ID for this connection                             |
| id            | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| bvlc_function | string    | BVLC Function                                             |
| pdu_type      | string    | APDU Service Type                                         |
| pdu_service   | string    | APDU Service Choice                                       |
| invoke_id     | count     | Unique ID for all outstanding confirmed request/ACK APDUs |
| result_code   | string    | Error Code or Reject/Abort Reason                         |

### Discovery Log (bacnet_discovery.log)

#### Overview

This log captures important fields for Who-Is, I-Am, Who-Has, and I-Have messages and logs them to **bacnet_discovery.log**.

These messages contain a lot of important discovery information and provide a lot of important information to fingerprint a BACnet network and basic information about the BACnet devices within the network.

#### Fields Captured

| Field             | Type      | Description                                                     |
| ----------------- |-----------|-----------------------------------------------------------------|
| ts                | time      | Timestamp                                                       |
| uid               | string    | Unique ID for this connection                                   |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)              |
| pdu_service       | string    | APDU Service Choice (who-is, i-am, who-has, or i-have)          |
| object_type       | string    | BACnet Device's Object Type                                     |
| instance_number   | count     | BACnet Device's Instance Number                                 |
| vendor            | string    | BACnet Device's Vendor Name                                     |
| range             | string    | Range of instance numbers                                       |
| object_name       | string    | Object name searching for (who-has) or responding with (i-have) |

### Property Log (bacnet_property.log)

#### Overview

This log captures important variables for Read-Property-Request, Read-Property-ACK, and Write-Property-Request messages and logs them to **bacnet_property.log**.

Read and Write Property Requests are the most common type of BACnet message and can contain extremely important information when looking for potentially malicious or bad traffic.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|---------------------------------------------------------- |
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| pdu_service       | string    | APDU Service Choice (read or write property services)     |
| object_type       | string    | BACnet Device's Object Type                               |
| instance_number   | count     | BACnet Device's Instance Number                           |
| property          | string    | Property Type                                             |
| array_index       | count     | Property Array Index                                      |
| value             | string    | Value of Property                                         |

## Testing

This parser has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from BACnet traffic used in our ICS Capture the Flag competition.