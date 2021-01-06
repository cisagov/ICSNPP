# Enhanced Zeek Modbus Protocol Parser

## Overview

This is an extension of the Modbus protocol parser in the Zeek NSM platform.

This is an updated version of the Modbus protocol parser that comes with a base/default Zeek installation. In a base/default Zeek installation, the only Modbus information that gets logged is the modbus.log file which provides a very high level overview of the Modbus traffic we can see, but doesn't provide a lot of detailed. In this updated parser, the modbus.log file from the original remains, but there are three added log files to give more information about the Modbus traffic.

There are currently 4 Zeek log files that can be output by this script.  These log files are defined in the [main.zeek](main.zeek) file.  Output log files include the following: 
* modbus.log
* modbus_detailed.log
* mask_write_register.log
* read_write_multiple_registers.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

**Note: These installation updates will soon be changed to prevent overwriting original Zeek scripts**
At this time we do not recommend following these installation updates on production systems until these updates have been made.

To install these updates, all you will need to do is overwrite the main.zeek file with in the Modbus scripts directory of your Zeek installation with the main.zeek file in this folder. 

If you have installed the Zeek development system and created Zeek from source code, the `${ZEEK_INSTALLATION_DIR}` is most likely `/usr/local/zeek`.
If you downloaded the 'pre-built' (i.e. compiled) version of Zeek, the `${ZEEK_INSTALLATION_DIR}` is most likely `/opt/zeek`.

The location of the Modbus scripts directory can be found at:
`${ZEEK_INSTALLATION_DIR}/share/zeek/base/protocols/modbus`

By copying the main.zeek file in this folder, Zeek will use this script instead of the default Modbus main.zeek and will parse out the log files defined in *Logging Capabilities*.

Example Linux Installation:
```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_modbus_parser/
zeek_install_dir=$(dirname $(dirname `which zeek`)) # Get base Zeek directory
sudo mv $zeek_install_dir/share/zeek/base/protocols/modbus/main.zeek $zeek_install_dir/share/zeek/base/protocols/modbus/main.zeek.old
sudo cp main.zeek $zeek_install_dir/share/zeek/base/protocols/modbus/ # Copy new main.zeek file into Modbus scripts directory
```

## Logging Capabilities

### Modbus Header Log (modbus.log)

#### Overview

This log captures Modbus header information for every Modbus packet and logs them to **modbus.log**.

This log file is the default log output for the original/base Modbus protocol parser that comes with Zeek. Along with the normal Zeek information (ts, uid, id), all this log shows us is the Modbus function code and any possible exception codes. 

#### Fields Captured

| Field         | Type      | Description                                               |
| ------------- |-----------|-----------------------------------------------------------|
| ts            | time      | Timestamp                                                 |
| uid           | string    | Unique ID for this connection                             |
| id            | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| func          | string    | Modbus function code                                      |
| exception     | string    | Exception response code (Response sent when errors occur) |

### Detailed Modbus Field Log (modbus_detailed.log)

#### Overview

This log captures additional Modbus fields and logs them to **modbus_detailed.log**.

This log file contains the functions (read/write), count, addresses, and values of Modbus coils, discrete inputs, input registers, and holding registers.

A "network_direction" meta-data field is also included in the log.  The "network_direction" column specifies whether the message was a *request* or a *response* message. 
If an exception arises in the Modbus data the exception code will be logged in the "values" field.

#### Fields Captured

| Field             | Type      | Description                                                       |
| ----------------- |-----------|-------------------------------------------------------------------|
| ts                | time      | Timestamp                                                         |
| uid               | string    | Unique ID for this connection                                     |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)                |
| uint_id           | count     | Modbus unit-id                                                    |
| func              | string    | Modbus function code                                              |
| network_direction | string    | Message network direction (request or response)                   |
| address           | count     | Starting address of value(s) field                                |
| quantity          | count     | Number of addresses/values read or written to                     |
| values            | string    | Value(s) or Coils, discrete_inputs, or registers read/written to  |


### Mask Write Register Log (mask_write_register.log)

#### Overview

This log captures the fields of a Modbus *mask_write_register* function (function code 0x16) and logs them to **modbus_write_register.log**.

#### Fields Captured

| Field             | Type      | Description                                           |
| ----------------- |-----------|-------------------------------------------------------|
| ts                | time      | Timestamp                                             |
| uid               | string    | Unique ID for this connection                         |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| uint_id           | count     | Modbus unit-id                                        |
| func              | string    | Modbus function code                                  |
| network_direction | string    | Message network direction (request or response)       |
| address           | count     | Address of the target register                        |
| and_mask          | count     | Boolean 'and' mask to apply to the target register    |
| or_mask           | count     | Boolean 'or' mask to apply to the target register     |

### Read Write Multiple Registers Log (read_write_multiple_registers.log)

#### Overview

This log captures the fields of a Modbus *read/write multiple registers* function (function code 0x17) and logs them to **read_write_multiple_registers.log**.

#### Fields Captured

| Field                 | Type      | Description                                           |
| ----------------------|-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| uint_id               | count     | Modbus unit-id                                        |
| func                  | string    | Modbus function code                                  |
| network_direction     | string    | Message network direction (request or response)       |
| write_start_address   | count     | Starting address of registers to be written           |
| write_registers       | string    | Register values written                               |
| read_start_address    | count     | Starting address of the registers to read             |
| read_quantity         | count     | Number of registers to read in                        |
| read_registers        | string    | Register values Read                                  |

## Testing

This script has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from various Modbus traffic including packet captures found online and traffic generated with the pymodbus library.
