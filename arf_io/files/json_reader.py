import json


class JSONReader:

    @staticmethod
    def read_file(path: str) -> dict:
        with open(path, "r") as file_stream:
            return json.load(file_stream)

    @staticmethod
    def read_file_by_line(path: str) -> list[dict]:
        content = []
        with open(path, 'r') as file:
            for line in file:
                try:
                    json_obj = json.loads(line).get("result").get("_raw")
                    content.append(json.loads(json_obj))
                except json.decoder.JSONDecodeError:
                    pass
        return content
