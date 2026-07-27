import logging
from pathlib import Path

import httpx
import polars as pl


LOGGER = logging.getLogger(__name__)

STATIONS_URL = 'https://ressources.data.sncf.com/api/explore/v2.1/catalog/datasets/liste-des-gares/exports/csv?lang=fr&timezone=Europe%2FParis&use_labels=true&delimiter=%3B'
STATIONS_CACHE_PATH = Path('tmp/trains/stations.csv')


def _fetch_stations_csv(cache_path: Path) -> Path:
  if cache_path.exists():
    return cache_path

  LOGGER.info(f'Downloading station list from {STATIONS_URL}')

  response = httpx.get(STATIONS_URL, follow_redirects=True, timeout=30)
  response.raise_for_status()

  cache_path.parent.mkdir(exist_ok=True, parents=True)
  cache_path.write_bytes(response.content)

  return cache_path


def load_stations(*, cache_path: Path = STATIONS_CACHE_PATH) -> pl.DataFrame:
  """Return the list of French passenger stations, downloading and caching the source CSV as needed."""

  csv_path = _fetch_stations_csv(cache_path)
  stations = pl.read_csv(csv_path, separator=';')

  return (
    stations
    .filter(pl.col('VOYAGEURS') == 'O')
    .select(
      code=pl.col('CODE_UIC'),
      name=pl.col('LIBELLE'),
      city=pl.col('COMMUNE'),
      longitude=pl.col('X_WGS84'),
      latitude=pl.col('Y_WGS84'),
    )
    .unique(subset=['code'])
    .sort('name')
  )
