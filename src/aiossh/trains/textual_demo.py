import functools
from collections.abc import Iterable
from typing import ClassVar, Optional, override

from textual.app import App, ComposeResult, SystemCommand
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import (
  Button,
  DataTable,
  Input,
  Label,
  Static,
  TabbedContent,
  TabPane,
)

from .matching import find_best_station_matches
from .stations import load_stations


_HIDDEN_SYSTEM_COMMANDS = {'Theme', 'Screenshot'}

_SNCF_LOGO = '''\
    ██████  ██   █  ██████  ██████
   ██      ███  █  ██      ██
  ██████  ██ █ █  ██      █████
     ██  ██  ██  ██      ██
██████  ██   █  ██████  ██
──────────────────────────────────'''

_TERMINAL_MONO_THEME = Theme(
  name='terminal-mono',
  primary='#f2f2ed',
  secondary='#8a8a85',
  accent='#f2f2ed',
  warning='#b0a06a',
  error='#b07a7a',
  success='#f2f2ed',
  foreground='#d8d8d2',
  background='#000000',
  surface='#050505',
  panel='#0a0a0a',
  boost='#111111',
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
    border: solid $primary;
  }

  TrainSearchPane #train-search-form Label {
    margin-top: 1;
    text-style: none;
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
    max-height: 80%;
    padding: 1 2;
    border: solid $primary;
  }

  TrainSearchPane #train-search-choices Button {
    margin-top: 1;
    width: 40;
  }

  TrainSearchPane #train-results-container {
    width: auto;
    padding: 1 2;
    border: solid $primary;
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
      Label('Gare de départ'),
      Input(id='departure-station-input', placeholder='ex. Paris'),
    ]

    if error is not None:
      children.append(Static(error, classes='train-search-error'))

    children.append(Button('Rechercher', id='train-search-submit'))

    await self.remove_children()
    await self.mount(Container(*children, id='train-search-form'))
    self.query_one('#departure-station-input', Input).focus()

  async def _show_choices(self, candidates: list[str]):
    self._candidates = candidates

    children = [Static('Plusieurs gares correspondent — choisissez-en une :')]
    children += [
      Button(name, id=f'train-search-choice-{index}')
      for index, name in enumerate(candidates)
    ]
    children.append(Button('Retour', id='train-search-back'))

    await self.remove_children()
    await self.mount(VerticalScroll(*children, id='train-search-choices'))

  async def _show_results(self, station: str):
    table = DataTable(id='train-results')
    table.add_columns('N° de train', 'Heure de départ', 'Destination')

    for train_number, departure_time, destination in _DUMMY_TRAINS:
      table.add_row(train_number, departure_time, destination)

    await self.remove_children()
    await self.mount(Container(
      Static(f'Trains au départ de {station}', id='train-results-title'),
      table,
      Button('Nouvelle recherche', id='train-search-again'),
      id='train-results-container',
    ))

  async def _submit_search(self, query: str):
    candidates = find_best_station_matches(query, _station_names())

    if not candidates:
      await self._show_form(error=f'Aucune gare ne correspond à « {query} ».')
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
  Screen {
    background: $background;
  }

  Vertical {
    align: center middle;
  }

  #banner {
    width: 100%;
    content-align: center middle;
    color: $primary;
    text-style: bold;
  }

  TabbedContent {
    background: $background;
    height: 1fr;
  }

  Tabs {
    background: $background;
  }

  Tab {
    text-style: none;
  }

  Underline {
    color: $primary;
  }

  Button {
    background: $background;
    color: $primary;
    border: solid $primary;
    text-style: none;
    min-width: 1;
  }

  Button:hover {
    background: $primary;
    color: $background;
    border: solid $primary;
  }

  Button:focus {
    text-style: bold;
  }

  #greeting {
    width: auto;
    padding: 1 2;
    border: solid $primary;
  }

  #hint-bar {
    width: 100%;
    content-align: center middle;
    color: $secondary;
    padding-bottom: 1;
  }
  '''

  BINDINGS: ClassVar = [('q', 'quit', 'Quitter')]

  def __init__(self, *, user_name: str, client_name: str):
    super().__init__()

    self.user_name = user_name
    self.client_name = client_name
    self.title = 'Trains SNCF'

    self.register_theme(_TERMINAL_MONO_THEME)
    self.theme = _TERMINAL_MONO_THEME.name

  @override
  def compose(self) -> ComposeResult:
    yield Static(_SNCF_LOGO, id='banner')

    with TabbedContent():
      with TabPane('Bienvenue', id='welcome'):
        with Vertical():
          yield Static(f'Bonjour, {self.user_name} !\nConnecté depuis {self.client_name} via aiossh.', id='greeting')
          yield Button('Quitter', id='quit')

      with TabPane('Recherche de train', id='train-search'):
        yield TrainSearchPane()

    yield Static("q quitter · tab / maj+tab changer d'onglet", id='hint-bar')

  def on_button_pressed(self, event: Button.Pressed):
    if event.button.id == 'quit':
      self.exit()

  @override
  def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
    for command in super().get_system_commands(screen):
      if command.title not in _HIDDEN_SYSTEM_COMMANDS:
        yield command
