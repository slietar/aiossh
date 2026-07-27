import functools
from collections.abc import Iterable
from typing import ClassVar, Optional, override

from textual.app import App, ComposeResult, SystemCommand
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import (
  Button,
  DataTable,
  Footer,
  Header,
  Input,
  Label,
  Log,
  Static,
  TabbedContent,
  TabPane,
)

from .matching import find_best_station_matches
from .stations import load_stations


_HIDDEN_SYSTEM_COMMANDS = {'Theme', 'Screenshot'}

_BLUE_GREY_THEME = Theme(
  name='blue-grey',
  primary='#4d9cff',
  secondary='#8fa8c4',
  accent='#4d9cff',
  warning='#8fa8c4',
  error='#6a7d94',
  success='#4d9cff',
  foreground='#c8d2dc',
  background='#05070a',
  surface='#0c1016',
  panel='#131922',
  boost='#1a212c',
  dark=True,
)


@functools.cache
def _station_names() -> list[str]:
  return load_stations()['name'].to_list()


_DUMMY_TRAINS = [
  ('8451', '08:12', 'Nice'),
  ('6724', '09:47', 'Nantes'),
  ('5310', '11:05', 'Paris'),
  ('9182', '13:30', 'Nice'),
  ('2247', '16:58', 'Nantes'),
]


class TrainSearchPane(Vertical):
  """
  A small self-contained state machine: enter a station name, resolve it (via fuzzy
  matching) to a real station, then show a dummy train table for that station.
  """

  DEFAULT_CSS = '''
  TrainSearchPane {
    align: center middle;
  }

  TrainSearchPane #train-search-form {
    width: auto;
    padding: 1 2;
    border: round $accent;
  }

  TrainSearchPane #train-search-form Label {
    margin-top: 1;
  }

  TrainSearchPane #train-search-form Input {
    width: 40;
  }

  TrainSearchPane #train-search-form .train-search-error {
    color: $error;
    margin-top: 1;
  }

  TrainSearchPane #train-search-choices {
    width: auto;
    padding: 1 2;
    border: round $accent;
  }

  TrainSearchPane #train-search-choices Button {
    margin-top: 1;
    width: 40;
  }

  TrainSearchPane #train-results-container {
    width: auto;
    padding: 1 2;
    border: round $accent;
  }

  TrainSearchPane #train-results-container #train-results-title {
    margin-bottom: 1;
  }

  TrainSearchPane #train-results-container Button {
    margin-top: 1;
  }
  '''

  _candidates: list[str]

  async def on_mount(self):
    await self._show_form()

  async def _show_form(self, *, error: Optional[str] = None):
    children: list[Static | Label | Input | Button] = [
      Label('Departure station'),
      Input(id='departure-station-input', placeholder='e.g. Paris'),
    ]

    if error is not None:
      children.append(Static(error, classes='train-search-error'))

    children.append(Button('Search', id='train-search-submit'))

    await self.remove_children()
    await self.mount(Container(*children, id='train-search-form'))
    self.query_one('#departure-station-input', Input).focus()

  async def _show_choices(self, candidates: list[str]):
    self._candidates = candidates

    children = [Static('Several stations match — pick one:')]
    children += [
      Button(name, id=f'train-search-choice-{index}')
      for index, name in enumerate(candidates)
    ]
    children.append(Button('Back', id='train-search-back'))

    await self.remove_children()
    await self.mount(Container(*children, id='train-search-choices'))

  async def _show_results(self, station: str):
    table = DataTable(id='train-results')
    table.add_columns('Train N°', 'Departure time', 'Destination')

    for train_number, departure_time, destination in _DUMMY_TRAINS:
      table.add_row(train_number, departure_time, destination)

    await self.remove_children()
    await self.mount(Container(
      Static(f'Trains from {station}', id='train-results-title'),
      table,
      Button('New search', id='train-search-again'),
      id='train-results-container',
    ))

  async def _submit_search(self, query: str):
    candidates = find_best_station_matches(query, _station_names())

    if not candidates:
      await self._show_form(error=f'No station found matching "{query}".')
    elif len(candidates) == 1:
      await self._show_results(candidates[0])
    else:
      await self._show_choices(candidates)

  async def on_input_submitted(self, event: Input.Submitted):
    if event.input.id == 'departure-station-input':
      event.stop()
      await self._submit_search(event.value)

  async def on_button_pressed(self, event: Button.Pressed):
    button_id = event.button.id or ''

    if button_id == 'train-search-submit':
      event.stop()
      await self._submit_search(self.query_one('#departure-station-input', Input).value)
    elif button_id in ('train-search-back', 'train-search-again'):
      event.stop()
      await self._show_form()
    elif button_id.startswith('train-search-choice-'):
      event.stop()
      index = int(button_id.removeprefix('train-search-choice-'))
      await self._show_results(self._candidates[index])


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

    self.register_theme(_BLUE_GREY_THEME)
    self.theme = _BLUE_GREY_THEME.name

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
        yield TrainSearchPane()

    yield Footer()

  def on_mount(self):
    table = self.query_one('#table-widget', DataTable)
    table.add_columns('Name', 'Client')
    table.add_row(self.user_name, self.client_name)

    log = self.query_one('#log-widget', Log)
    log.write_line(f'{self.user_name} connected from {self.client_name}')

  def on_button_pressed(self, event: Button.Pressed):
    if event.button.id == 'quit':
      self.exit()

  @override
  def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
    for command in super().get_system_commands(screen):
      if command.title not in _HIDDEN_SYSTEM_COMMANDS:
        yield command
