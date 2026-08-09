import logging
import os
from datetime import datetime, timedelta
from urllib.parse import quote

import httpx
import polars as pl


LOGGER = logging.getLogger(__name__)

DEPARTURES_URL_TEMPLATE = 'https://api.sncf.com/v1/coverage/sncf/stop_areas/{stop_area_id}/departures'


async def fetch_departures(
  station_id: str,
  *,
  token: str | None = None,
  from_datetime: datetime | None = None,
  duration: timedelta = timedelta(days=1),
  count: int = 100,
) -> pl.DataFrame:
  """Fetch departures for the given train station id (e.g. '87686006') as a Polars DataFrame.

  `from_datetime` (defaults to now) and `duration` define the time window to search within
  (e.g. pass `from_datetime=now - timedelta(hours=1)` and `duration=timedelta(hours=4)` to
  get departures from 1 hour ago to 3 hours from now). `count` caps the number of results
  and should be raised if a wide window is truncated.
  """

  token = token or os.environ['SNCF_API_TOKEN']
  stop_area_id = quote(f'stop_area:SNCF:{station_id}')
  url = DEPARTURES_URL_TEMPLATE.format(stop_area_id=stop_area_id)

  params: dict = {'count': count, 'duration': int(duration.total_seconds())}

  if from_datetime is not None:
    params['from_datetime'] = from_datetime.strftime('%Y%m%dT%H%M%S')

  async with httpx.AsyncClient() as client:
    response = await client.get(url, auth=(token, ''), params=params, timeout=30)

  response.raise_for_status()

  departures = response.json()['departures']

  return pl.DataFrame(
    {
      'departure_time': [d['stop_date_time']['departure_date_time'] for d in departures],
      'realtime': [d['stop_date_time']['data_freshness'] == 'realtime' for d in departures],
      'network': [d['display_informations']['network'] for d in departures],
      'line': [d['display_informations']['code'] for d in departures],
      'mode': [d['display_informations']['commercial_mode'] for d in departures],
      'physical_mode': [d['display_informations']['physical_mode'] for d in departures],
      'train_number': [d['display_informations']['trip_short_name'] for d in departures],
      'direction': [d['display_informations']['direction'] for d in departures],
    },
  ).with_columns(
    pl.col('departure_time').str.to_datetime('%Y%m%dT%H%M%S'),
  )
