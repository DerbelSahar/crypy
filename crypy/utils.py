from collections.abc import Iterable
from typing import Optional
import sys
from operator import itemgetter


class Menu:
    '''Display a menu and respond to choices when run.'''
    def __init__(self, choices: Optional[Iterable] = None, include_quit: bool = True,
                 once: bool = True, choice_message: str = "Enter an option: ",
                 quit_message: Optional[str] = "Quitting", include_back: bool = False
    ):
        if not choices:
            choices = []
        self.choices = choices
        self.once = once
        self.choice_message = choice_message
        self.include_back = include_back
        self.include_quit = include_quit

        if self.include_back:
            choices.append(("Back", lambda : "GO_BACK"))
        
        if self.include_quit:
            choices.append(("Quit", self.quit))
        
        self.quit_message = quit_message
    
    @property
    def actions(self):
        return list(map(itemgetter(1), self.choices))
    
    @property
    def descriptions(self):
        return list(map(itemgetter(0), self.choices))

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
                break


    def quit(self):
        if self.quit_message:
            print(self.quit_message)
        sys.exit(0)

if __name__ == "__main__":
    Menu([("hello", lambda: print("hello"))], once=True, include_quit=True, include_back=False).run()