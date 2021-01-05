# Ethernet/IP and CIP Zeek Parser Plugin

## Overview

This is an Ethernet/IP and CIP parser developed for the Zeek NSM platform. 

This parser has been developed as a Zeek plugin that can be added to existing Zeek installations and log important fields and variables within the Ethernet/IP (ENIP) and CIP protocols. This parser was developed to be fully customizable, so if you would like to drill down into specific ENIP or CIP packets and log certain variables, all you need to do is add the logging functionality to the scripts/main.zeek file. The functions within the [scripts/main.zeek](scripts/main.zeek) and [src/events.bif](src/events.bif) file should prove to be a good guide on how to add new logging functionality.

There are currently 4 Zeek log files that can be output by this parser. These log files are defined in the [scripts/main.zeek](scripts/main.zeek) file.
* enip.log
* cip.log
* cip_io.log
* cip_identity.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_enip_parser/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see Zeek::ENIP
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see Zeek::ENIP
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the Zeek_Enip.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Enip.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### ENIP Header Log (enip.log)

#### Overview

This log captures Ethernet/IP header information for every Ethernet/IP packet and logs it to **enip.log**.

While the session_handle and sender_context fields can be useful in correlating packets between hosts, the command and status fields are the most interesting Ethernet/IP-specific fields.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| enip_command      | string    | Ethernet/IP Command                                       |
| length            | count     | Length of ENIP data following header                      |
| session_handle    | string    | Session Identifier                                        |
| enip_status       | string    | Ethernet/IP Status Code                                   |
| sender_context    | string    | Sender Context                                            |
| options           | string    | Options Flags                                             |

### CIP Header Log (cip.log)

#### Overview

This log captures CIP header information for every CIP packet and logs it to **cip.log**.

The vast majority of Ethernet/IP traffic is used to send encapsulated CIP traffic. The service and status fields show the CIP-specific service type and result, while the request path fields can give a lot more detail about the CIP device.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| cip_sequence_count    | count     | CIP sequence number                                       |
| direction             | string    | Request or Response                                       |
| cip_service           | string    | CIP service type                                          |
| cip_status            | string    | CIP status code                                           |
| class_id              | string    | CIP Request Path - Class ID                               |
| class_name            | string    | CIP Request Path - Class Name                             |
| instance_id           | string    | CIP Request Path - Instance ID                            |
| attribute_id          | string    | CIP Request Path - Attribute ID                           |
| data_id               | string    | CIP Request Path - Data ID                                |
| other_id              | string    | CIP Request Path - Other ID                               |

### CIP I/O Log (cip_io.log)

#### Overview

This log captures CIP I/O (input-output) data for every CIP IO packet and logs it to **cip_io.log**.

CIP I/O messages are used to send data quickly between ICS devices and do not follow the packet structure of normal CIP packets. The data in the field is fully customizable per device/manufacturer so unfortunately there is no way to parse the data any further.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| connection_id         | string    | Connection Identifier                                     |
| sequence_number       | count     | Sequence Number within Connection                         |
| data_length           | count     | Length of data in io_data field                           |
| io_data               | string    | CIP IO data                                               |

### CIP Identity Log (cip_identity.log)

#### Overview

This log captures important variables for CIP_Identity objects and logs them to **cip_identity.log**.

CIP Identity objects are returned via the Ethernet/IP "List_Identity" command and contain a lot of useful information about a CIP device.

#### Fields Captured

| Field                 | Type      | Description                                           |
| --------------------- |-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| encapsulation_version | count     | Encapsulation protocol version supported              |
| socket_address        | addr      | Socket address IP address                             |
| socket_port           | count     | Socket address port number                            |
| vendor_id             | count     | Vendor ID                                             |
| vendor_name           | string    | Name of Vendor                                        |
| device_type_id        | count     | Device type ID                                        |
| device_type_name      | string    | Name of device type                                   |
| product_code          | count     | Product code assigned to device                       |
| revision              | string    | Device revision (major.minor)                         |
| device_status         | string    | Current status of device                              |
| serial_number         | string    | Serial number of device                               |
| product_name          | string    | Human readable description of device                  |
| device_state          | string    | Current state of the device                           |

## Testing

This parser has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from combining various packet captures found online as well as traffic captured in Idaho National Laboratory's (INL) Control Environment Laboratory Resource (CELR).
