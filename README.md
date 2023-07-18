# Attack Replay Framework (ARF)

*Verify the exploitability of well-known vulnerabilities using detected attack attempts*

For an overview of all ARF related projects/dependencies, please refer to [GitHub](https://github.com/dial25sd/arf-overview).

## Caution

- Unauthorized use of this application might be illegal. Consider reading the docs before execution.

## Setup

1. Clone this repo and install the dependencies using `pip install -r requirements.txt` (consider using a virtual
   environment).
1. Install the metasploit framework.
1. Make sure `msfrpc` is in your `$PATH` and the MSF DB has been initialized (e.g. by executing `msfdb init`).  
   You're good to go, when you can start `msfconsole` without any prompts before the banner.
1. Install MongoDB and start it.
1. Install docker, afterwards:
   1. Make sure that docker is actually executable as non-sudo user. If this isn't the case yet, follow the steps at [Docker Docs](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user).
   1. Enable IPv6 support using the steps provided by [Docker Docs](https://docs.docker.com/config/daemon/ipv6/#use-ipv6-for-the-default-bridge-network).
   1. Depending on the OS used, you might also need to make sure docker service is running.
1. Temporary workaround:  
clone the pymetasploit3 repo from [GitHub](https://github.com/dial25sd/pymetasploit3) and copy the `pymetasploit3/pymetasploit3` folder to the `attack-replay` repo: `cp -r pymetasploit3/pymetasploit3 attack-replay/`.
1. Clone the attack-replay-modules repository to a directory of your choice.

## Usage

### General
- You can gracefully stop the application at any time using CTRL+C.  
  If there is report data to write, a potentially incomplete report will be written. Logs will be saved nevertheless.
- Use `-h`or `--help` for an overview of options. 

### Command line arguments:
```bash
attack-replay.py -r MODULE_REPO_DIR -x REPORT_DIR -l LHOST
              [-e EVENT_FILE]
              [-s SUBNET] [-n SUBNET_FILE]
              [-d DB_HOST] [-p DB_PORT] [-a DB_NAME]
              [-t MODULE_TIMEOUT] [-o THRESHOLD]
              [-c] [-m] [-v]
```

where:

- `-r`, `--repo MODULE_REPO_DIR`  
  Location of the attack-replay-modules repository. (Required)
- `-x`, `--report REPORT_DIR`  
  Directory to write the application's report to. (Required)
- `-e`, `--event-file EVENT_FILE`  
  Read the SIEM events from this JSON file. Can either contain one JSON object per line or one JSON array. (Optional)
- `-s`, `--subnet SUBNET` / `-n`, `--subnet-file SUBNET_FILE`  
  Single internal subnet that modules can be executed against, specified with netmask (e.g., '192.168.0.0/24'), or a .txt file that specifies all subnets that modules can be executed against, with one subnet per line. One of these is required.
- `-l`, `--lhost LHOST`  
  IP of the exploit executing machine on the network interface used for executing the exploit. (Required)
- `-d`, `--db-host DB_HOST`  
  IP or hostname of the DB server to use. Defaults to '127.0.0.1'. (Optional)
- `-p`, `--db-port DB_PORT`  
  Port number of the DB server to use. Defaults to 27017. (Optional)
- `-a`, `--db-name DB_NAME`  
  Name of the DB to use. Defaults to 'arf'. (Optional)
- `-t`, `--timeout MODULE_TIMEOUT`  
  Timeout in seconds that a single module is allowed to run. Defaults to 180s. (Optional)
- `-o`, `--threshold THRESHOLD`  
  Threshold in seconds that a given CVE is not verified again on a specific host. Defaults to 1800s. (Optional)
- `-c`, `--continuous`  
  Set this flag if the application should run in continuous mode. (Optional, mutually exclusive with `-m`)
- `-m`, `--manual`  
  Set this flag if the user should be prompted for parameter values. (Optional, mutually exclusive with `-c`)
- `-v`, `--verbose`  
  Set this flag if output should be more verbose and include debugging info. (Optional)

### Further configuration

Find more config options, beyond the command line arguments from above, in the `config.py` file.

## Examples
- `python attack-replay.py -r ../attack-replay-modules/ -n data_templates/internal_subnets_private.txt -l 10.10.10.1 -x ./ -t 120 -o 1800 -c`:  
  run the framework in continuous mode while only verifying hosts with private IPs that have not been verified in the last 30 minutes.
- `python attack-replay.py -r /home/xyz/attack-replay-modules/ -s 10.10.0.0/16 -e data_templates/events.json -t 60 -l 10.10.10.1 -x /home/s/Dokumente/MA_local/attack-replay/ -o 900 -v`:  
  let the framework read the events from the given file, verify only hosts on the given /16 subnet and be verbose.

## Results
- Read the results from the CSV report generated at the location specified by `-x`. You might especially want to look for hosts with an `overall_result` of `EXPLOITABLE` or `VULNERABLE`.
- You can also correlate the report with the logs (stored at `./attack-replay.log`) using the field `event_id`. 