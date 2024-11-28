from json import dumps

class Service:
    def __init__(self, name, config):
        self.name = name
        self.config = config
    def __str__(self):
        return dumps(self.__dict__)