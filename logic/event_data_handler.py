from json.decoder import JSONDecodeError

from arf_io.db import DbHandler
from arf_io.exceptions import ExceptionHandler
from arf_io.files import JSONReader
from arf_io.ui import ArfLogger
from data_models.shared import SiemEvent


class EventDataHandler:

    def __init__(self, db: DbHandler):
        self.logger = ArfLogger.instance()
        self.db = db
        self.exception_handler = ExceptionHandler()

    def read_and_cache_events(self, file_path: str) -> None:
        self.logger.debug(f"Parsing and caching SIEM events...")
        events = self.__read_events(json_file_path=file_path)
        self.db.write_siem_events(events)

    def __read_events(self, json_file_path: str) -> list[SiemEvent]:
        try:
            try:
                json = JSONReader.read_file(path=json_file_path)
                try:
                    events = [SiemEvent.from_json(event_json) for event_json in json]
                except AttributeError:  # JSON object may not be a list
                    events = [SiemEvent.from_json(json)]
            except JSONDecodeError:  # file may contain multiple, separate JSON objects
                json = JSONReader.read_file_by_line(path=json_file_path)
                events = [event for event_json in json if (event := SiemEvent.from_json(event_json))]
            for event in events:
                self.logger.debug(f"Read event: {event}", 1)
            return events
        except Exception as e:
            self.exception_handler.handle(e, msg=f"Unable to read event from file: {e}", reraise=True)
