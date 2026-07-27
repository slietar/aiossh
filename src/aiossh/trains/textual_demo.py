from collections.abc import Iterable
from typing import ClassVar, override

from textual.app import App, ComposeResult, SystemCommand
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import (
  Button,
  DataTable,
  Footer,
  Header,
  Label,
  Log,
  Select,
  Static,
  TabbedContent,
  TabPane,
)


_HIDDEN_SYSTEM_COMMANDS = {'Theme', 'Screenshot'}

_STATIONS = ['Paris', 'Nice', 'Nantes']

_DUMMY_TRAINS = [
  ('8451', '08:12', 'Nice'),
  ('6724', '09:47', 'Nantes'),
  ('5310', '11:05', 'Paris'),
  ('9182', '13:30', 'Nice'),
  ('2247', '16:58', 'Nantes'),
]


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

  #train-search-form {
    width: auto;
    padding: 1 2;
    border: round $accent;
  }

  #train-search-form Label {
    margin-top: 1;
  }

  #train-search-form Select {
    width: 40;
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

    with TabbedContent():
      with TabPane('Welcome', id='welcome'):
        with Vertical():
          yield Static(f'Hello, {self.user_name}!\nConnected from {self.client_name} via aiossh.', id='greeting')
          yield Button('Quit', id='quit')

      with TabPane('Table', id='table'):
        yield DataTable(id='table-widget')

      with TabPane('Log', id='log'):
        yield Log(id='log-widget')

      with TabPane('Train search', id='train-search'):
        with Vertical(id='train-search-form'):
          yield Label('Departure station')
          yield Select(
            [(station, station) for station in _STATIONS],
            id='departure-station',
            prompt='Select a station',
          )
          yield Button('Search', id='train-search-submit')

        yield DataTable(id='train-results')

    yield Footer()

  def on_mount(self):
    table = self.query_one('#table-widget', DataTable)
    table.add_columns('Name', 'Client')
    table.add_row(self.user_name, self.client_name)

    log = self.query_one('#log-widget', Log)
    log.write_line(f'{self.user_name} connected from {self.client_name}')

    results = self.query_one('#train-results', DataTable)
    results.add_columns('Train N°', 'Departure time', 'Destination')

  def on_button_pressed(self, event: Button.Pressed):
    if event.button.id == 'quit':
      self.exit()
    elif event.button.id == 'train-search-submit':
      self._search_trains()

  def _search_trains(self):
    results = self.query_one('#train-results', DataTable)
    results.clear()

    for train_number, departure_time, destination in _DUMMY_TRAINS:
      results.add_row(train_number, departure_time, destination)

  @override
  def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
    for command in super().get_system_commands(screen):
      if command.title not in _HIDDEN_SYSTEM_COMMANDS:
        yield command
