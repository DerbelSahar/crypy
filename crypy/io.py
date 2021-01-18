from abc import ABC, abstractmethod, ABCMeta
from .utils import CLIMenu, StreamlitMenu


class IOService(ABC):
    @abstractmethod
    def get_menu_class(self):
        pass

    @abstractmethod
    def input(self) -> str:
        pass

    @abstractmethod
    def print(self, message: str):
        pass
    
    @abstractmethod
    def open_file(self):
        pass

class CLIService(IOService):
    def get_menu_class(self):
        return CLIMenu
    
    def input(self, message: str) -> str:
        return input(message + "\n")

    
    def print(self, message: str):
        print(message)
    
    
    def open_file(self):
        filename = self.input("enter the file name")
        file = open(filename, 'rb')
        return file

    
class StreamlitService(IOService):
    def get_menu_class(self):
        return StreamlitMenu