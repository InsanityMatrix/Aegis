from json import dumps

class Service:
    def __init__(self, name, config):
        self.name = name
        self.config = config
    
    def __str__(self):
        return dumps(self.to_dict(), indent=2)
    
    def to_dict(self):
        # Convert the Service instance to a dictionary
        return {
            "name": self.name,
            "config": self.config
        }

    @classmethod
    def from_dict(cls, data):
        # Create a Service instance from a dictionary
        return cls(data["name"], data["config"])