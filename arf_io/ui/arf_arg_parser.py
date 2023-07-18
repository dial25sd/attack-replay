from argparse import ArgumentParser, Namespace
from typing import Any, Callable

from arf_io.exceptions import ArfArgumentValidationError
from ..files.txt_reader import TxtReader
from utils import IPNetwork, IpUtils, ValidatorUtils
from .arf_logger import ArfLogger


class ArfArgParser:

    def __init__(self):
        self.logger = ArfLogger.instance()

    def parse_args(self) -> Namespace:
        arg_parser = ArgumentParser(
            description="attack-replay - Verify the exploitability of well-known vulnerabilities using detected attack attempts")
        arg_parser.add_argument("-r", "--repo",
                                dest="module_repo",
                                help="Location of the attack-replay-modules repository.",
                                metavar="module_repo_path",
                                type=(lambda x: self.__validate(x, "-r/--repo", lambda x: ValidatorUtils.validate_writable_dir(x))),
                                required=True)
        arg_parser.add_argument("-x", "--report",
                                dest="report_dir",
                                help="Directory to write the application's report to.",
                                metavar="report_dir",
                                type=(lambda x: self.__validate(x, "-x/--report", lambda x: ValidatorUtils.validate_writable_dir(x))),
                                required=True)
        arg_parser.add_argument("-e", "--event-file",
                                dest="event_file",
                                help="Read the SIEM events from this JSON file. Can either contain one JSON object per line or one JSON array.",
                                metavar="siem_event_filepath",
                                type=(lambda x: self.__validate(x, "-e/--event-file", lambda x: ValidatorUtils.validate_readable_filepath(x))),
                                required=False)
        subnet_group = arg_parser.add_mutually_exclusive_group(required=True)
        subnet_group.add_argument("-s", "--subnet",
                                  dest="subnet",
                                  help="Single internal subnet that modules can be executed against. To be specified with netmask (eg '192.168.0.0/24').",
                                  metavar="subnet",
                                  type=(lambda x: self.__validate(x, "-s/--subnet", lambda x: IpUtils.validate_subnet(x), required=False)))
        subnet_group.add_argument("-n", "--subnet-file",
                                  dest="subnet_file",
                                  help="File that specifies all subnets that modules can be executed against. Provide a .txt file with one subnet per line.",
                                  metavar="subnet_filepath",
                                  type=(lambda x: self.__validate(x, "-n/--subnet-file", lambda x: ValidatorUtils.validate_readable_filepath(x), required=False)))
        arg_parser.add_argument("-l", "--lhost",
                                dest="lhost",
                                help="IP of the exploit executing machine on the network interface used for executing the exploit.",
                                metavar="ip_address",
                                type=(lambda x: self.__validate(x, "-l/--lhost", lambda x: IpUtils.validate_ip_addr(x))),
                                required=True)
        db_group = arg_parser.add_argument_group("database options", "Specify the connection details of the MongoDB to use.")
        db_group.add_argument("-d", "--db-host",
                              dest="db_host",
                              help="IP or hostname of the DB server to use. Defaults to 127.0.0.1",
                              metavar="ip_address",
                              type=(lambda x: self.__validate(x, "-d/--db-host", lambda x: IpUtils.validate_ip_addr(x))),
                              default="127.0.0.1")
        db_group.add_argument("-p", "--db-port",
                              dest="db_port",
                              help="Port of the DB server to use. Defaults to 27017.",
                              metavar="port_number",
                              type=(lambda x: self.__validate(x, "-p/--db-port", lambda x: ValidatorUtils.validate_port(x))),
                              default=27017)
        db_group.add_argument("-a", "--db-name",
                              dest="db_name",
                              help="Name of the DB to use. Defaults to 'arf'.",
                              metavar="db_name",
                              type=str,
                              default="arf")
        arg_parser.add_argument("-t", "--timeout",
                                dest="module_timeout",
                                help="Timeout in seconds that a single module is allowed to run. Defaults to 180s.",
                                metavar="seconds",
                                default=180,
                                type=(lambda x: self.__validate(x, "-t/--timeout", lambda x: ValidatorUtils.validate_timespan(x))),
                                required=False)
        arg_parser.add_argument("-o", "--threshold",
                                dest="threshold",
                                help="Threshold in seconds that a given CVE is not verified again on a specific host. Defaults to 1800s.",
                                metavar="seconds",
                                default=1800,
                                type=(lambda x: self.__validate(x, "-o/--threshold", lambda x: ValidatorUtils.validate_timespan(x))),
                                required=False)
        mode_group = arg_parser.add_mutually_exclusive_group(required=False)
        mode_group.add_argument("-c", "--continuous",
                                dest="continuous_mode",
                                action="store_true",
                                help="Set this flag if the application should run in continuous mode.",
                                default=False,
                                required=False)
        mode_group.add_argument("-m", "--manual",
                                dest="manual_mode",
                                action="store_true",
                                help="Set this flag if the user should be prompted for parameter values.",
                                default=False,
                                required=False)
        arg_parser.add_argument("-v", "--verbose",
                                dest="verbose",
                                action="store_true",
                                help="Set this flag if output should be more verbose and include debugging info.",
                                default=False,
                                required=False)
        self.logger.debug("Parsing params...")
        try:
            args = arg_parser.parse_args()
            args.subnets = self.__validate_subnet_file(args.subnet, args.subnet_file)
            return args
        except ArfArgumentValidationError as e:
            arg_parser.error(str(e))

    def __validate(self, value: Any, param_name: str, validation_function: Callable[[Any], Any], required=True) -> Any:
        if value is None and not required:
            return None
        try:
            validated_param = validation_function(value)
            self.logger.debug(f"Set param '{param_name}' to '{validated_param}'.", 1)
            return validated_param
        except Exception as e:
            raise ArfArgumentValidationError(f"argument {param_name}: {e}") from e

    def __validate_subnet_file(self, subnet, subnet_file_path: str) -> list[IPNetwork]:
        if subnet:
            return [IpUtils.validate_subnet(subnet)]
        content = TxtReader().read_file(subnet_file_path)
        subnets = []
        if content and isinstance(content, list):
            for element in content:
                try:
                    subnets.append(IpUtils.validate_subnet(element.strip()))
                except Exception:
                    self.logger.warn(f"Cannot validate subnet '{element.strip()}', skipping!")
        if not subnets:
            raise ArfArgumentValidationError("Unable to validate subnets: No internal subnet specified correctly.")
        self.logger.info(f"Read {len(subnets)} internal subnets from file.")
        return subnets
