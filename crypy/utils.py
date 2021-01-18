from collections.abc import Iterable
from typing import Optional
import sys
from operator import itemgetter
from abc import ABC, abstractmethod, ABCMeta


class Menu(ABC):
    choices = []
    
    '''Display a menu and respond to choices when run.'''
    def __init__(self, choices: Optional[Iterable] = None, include_quit: bool = True,
                 once: bool = True, choice_message: str = "Enter an option: ",
                 quit_message: Optional[str] = "Quitting", include_back: bool = False
    ):
        if not choices:
            choices = []
        self.choices = list(choices)
        self.once = once
        self.choice_message = choice_message
        self.include_back = include_back
        self.include_quit = include_quit

        if self.include_back:
            self.choices.append(("Back", lambda : "GO_BACK"))
        
        if self.include_quit:
            self.choices.append(("Quit", self.quit))
        
        self.quit_message = quit_message
    
    @property
    def actions(self):
        return list(map(itemgetter(1), self.choices))
    
    @property
    def descriptions(self):
        return list(map(itemgetter(0), self.choices))

    @abstractmethod
    def display_menu(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def quit(self):
        pass

class StreamlitMenu(Menu):
    pass

class CLIMenu(Menu):
    def display_menu(self):
        message_template = "{index}- {description}"

        print("\n".join(
            [
                message_template.format(index=index, description=description)
                for index, description in enumerate(self.descriptions, start=1)
            ]
        ))

    def run(self):
        '''Display the menu and respond to choices.'''
        while True:
            self.display_menu()
            try:
                choice = int(input("Enter an option: "))
                action = self.actions[choice-1]
            except:
                print("Invalid input, retry...")
                continue

            if action:
                result = action()
                if result == "GO_BACK":
                    break
            if self.once:
                return result
        return result

    def quit(self):
        if self.quit_message:
            print(self.quit_message)
        sys.exit(0)


class MenuProvider(ABC):
    @abstractmethod
    def provide_menu(self) -> Menu:
        pass


if __name__ == "__main__":
    Menu([("hello", lambda: print("hello"))], once=True, include_quit=True, include_back=False).run()