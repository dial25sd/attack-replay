import random
import string


class RandomUtils:

    @staticmethod
    def get_random_port() -> int:
        return random.randint(49152, 65535)

    @staticmethod
    def get_random_password() -> str:
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
