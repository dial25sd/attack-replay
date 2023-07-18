class TxtReader:

    @staticmethod
    def read_file(path: str) -> list:
        with open(path, "r") as file_stream:
            return file_stream.readlines()
