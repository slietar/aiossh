from typing import ClassVar, override

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Footer, Header, Static


class DemoApp(App):
  """A minimal Textual app, served directly over the SSH connection via `SSHDriver`."""

  CSS = '''
  Vertical {
    align: center middle;
  }

  #greeting {
    width: auto;
    padding: 1 2;
    border: round $accent;
  }
  '''

  BINDINGS: ClassVar = [('q', 'quit', 'Quit')]

  def __init__(self, *, user_name: str, client_name: str):
    super().__init__()

    self.user_name = user_name
    self.client_name = client_name

  @override
  def compose(self) -> ComposeResult:
    yield Header()

    with Vertical():
      yield Static(f'Hello, {self.user_name}!\nConnected from {self.client_name} via aiossh.', id='greeting')
      yield Button('Quit', id='quit')

    yield Footer()

  def on_button_pressed(self, event: Button.Pressed):
    if event.button.id == 'quit':
      self.exit()
