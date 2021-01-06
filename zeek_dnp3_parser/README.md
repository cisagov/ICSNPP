# Enhanced Zeek DNP3 Protocol Parser

## Overview

This is an extension of the DNP3 protocol parser in the Zeek NSM platform.

This is an updated version of the DNP3 protocol parser that comes with a base/default Zeek installation. In a base/default Zeek installation, the only DNP3 log information that gets logged is the dnp3.log file which provides a very high level overview of the DNP3 traffic we can see, but doesn't provide a lot of detail. In this updated parser, the dnp3.log file from the original remains, but there are two added log files to give more information about the DNP3 traffic.

There are currently 3 Zeek log files that can be output by this parser. These log files are defined in the [main.zeek](main.zeek) file.
* dnp3.log
* dnp3_control.log
* dnp3_objects.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

**Note: These installation updates will soon be changed to prevent overwriting original Zeek scripts**
At this time we do not recommend following these installation updates on production systems until these updates have been made.

To install these updates, all you will need to do is overwrite the files in the DNP3 scripts directory of your Zeek installation. 

If you have installed the Zeek development system and created Zeek from source code, the `${ZEEK_INSTALLATION_DIR}` is most likely `/usr/local/zeek`.
If you downloaded the 'pre-built' (i.e. compiled) version of Zeek, the `${ZEEK_INSTALLATION_DIR}` is most likely `/opt/zeek`.

The location of the DNP3 scripts directory can be found at:
`${ZEEK_INSTALLATION_DIR}/share/zeek/base/protocols/dnp3`

By copying the three Zeek files in this folder (**\_\_load__.zeek**, **consts.zeek**, and **main.zeek**), Zeek will use these scripts instead of the default DNP3 scripts and will parse out the log files defined in *Logging Capabilities*.

Example Linux Installation:
```bash
git clone https://github.com/cisagov/icsnpp.git
cd icsnpp/zeek_dnp3_parser/
zeek_install_dir=$(dirname $(dirname `which zeek`)) # Get base Zeek directory
sudo mv $zeek_install_dir/share/zeek/base/protocols/dnp3/main.zeek $zeek_install_dir/share/zeek/base/protocols/dnp3/main.zeek.old
sudo mv $zeek_install_dir/share/zeek/base/protocols/dnp3/consts.zeek $zeek_install_dir/share/zeek/base/protocols/dnp3/consts.zeek.old
sudo cp *.zeek $zeek_install_dir/share/zeek/base/protocols/dnp3/ # Copy new main.zeek and consts.zeek files into DNP3 scripts directory
```

## Logging Capabilities

### DNP3 Header Log (dnp3.log)

#### Overview

This log captures DNP3 header information for each DNP3 request/reply packet-pair it sees and logs them to **dnp3.log**.

This log file is the default log output for the original/base DNP3 protocol parser that comes with Zeek. Along with the normal Zeek information (ts, uid, id), all this log shows us is the function code request/reply commands and the DNP3 iin field.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| fc_request        | string    | DNP3 Function Code in request                             |
| fc_reply          | string    | DNP3 Function Code in reply                               |
| iin               | count     | DNP3 internal indication number                           |

### DNP3 Control Log (dnp3_control.log)

#### Overview

This log captures DNP3 Control Relay Output Block and Pattern Control Block data seen in SELECT-OPERATE-RESPONSE commands and logs them to **dnp3_control.log**.

DNP3 Control Relay Output Blocks can be controlled via DNP3 SELECT and OPERATE commands and are among the most common (and most impactful) DNP3 commands.

This log file contains all the relevant data for these SELECT and OPERATE commands (as well as the responses) and shows a more in-depth look at these commands and provides a much more detailed look as to what operational DNP3 commands are being sent.

#### Fields Captured:

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| block_type            | string    | Control_Relay_Output_Block or Pattern_Control_Block       |
| function_code         | string    | Function Code (SELECT, OPERATE, RESPONSE)                 |
| index_number          | count     | Object Index #                                            |
| trip_control_code     | string    | Nul, Close, or Trip                                       |
| operation_type        | string    | Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off             |
| execute_count         | count     | Number of times to execute                                |
| on_time               | count     | On Time                                                   |
| off_time              | count     | Off Time                                                  |
| status_code           | string    | Status Code                                               |

### DNP3 Read Object Log (dnp3_read_objects.log)

#### Overview

This log captures DNP3 Read Object data seen in READ-RESPONSE commands and logs them to **dnp3_objects.log**.

DNP3 READ-RESPONSE commands are very common DNP3 commands and these responses contain a lot of useful information about the DNP3 devices.

#### Fields Captured

| Field                 | Type      | Description                                           |
| --------------------- |-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| function_code         | string    | Function Code (READ or RESPONSE)                      |
| object_type           | string    | DNP3 Object type                                      |
| object_count          | count     | Number of objects                                     |
| range_low             | count     | Range (Low) of object                                 |
| range_high            | count     | Range (High) of object                                |

## Testing

This script has been tested on the current Zeek LTS Release (Zeek 3.0.12) on various Linux machines.

The [Examples](examples) directory contains a packet capture (and resulting Zeek logs) taken from DNP3 traffic within Idaho National Laboratory's (INL) Control Environment Laboratory Resource (CELR).
