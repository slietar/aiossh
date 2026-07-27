import re
import unicodedata


def normalize(text: str) -> str:
  decomposed = unicodedata.normalize('NFKD', text)
  stripped = ''.join(char for char in decomposed if not unicodedata.combining(char))

  return re.sub(r'[^a-z0-9]+', '', stripped.lower())


def levenshtein_distance(a: str, b: str) -> int:
  if not a:
    return len(b)
  if not b:
    return len(a)

  previous_row = list(range(len(b) + 1))

  for i, char_a in enumerate(a, start=1):
    current_row = [i]

    for j, char_b in enumerate(b, start=1):
      cost = 0 if char_a == char_b else 1
      current_row.append(min(
        previous_row[j] + 1,
        current_row[j - 1] + 1,
        previous_row[j - 1] + cost,
      ))

    previous_row = current_row

  return previous_row[-1]


def substring_distance(pattern: str, text: str) -> int:
  """
  Edit distance from `pattern` to its closest-matching substring of `text`.

  Unlike a plain Levenshtein distance, this doesn't penalize `text` for having extra
  characters before or after the match — so searching "universite" against
  "grenobleuniversitesgieres" scores near 0 instead of scoring against the whole name.
  """

  if not pattern:
    return 0
  if not text:
    return len(pattern)

  # Free start: matching can begin at any position in `text` at no cost.
  previous_row = [0] * (len(text) + 1)

  for i, char_p in enumerate(pattern, start=1):
    current_row = [i]

    for j, char_t in enumerate(text, start=1):
      cost = 0 if char_p == char_t else 1
      current_row.append(min(
        previous_row[j] + 1,
        current_row[j - 1] + 1,
        previous_row[j - 1] + cost,
      ))

    previous_row = current_row

  # Free end: the match can also finish at any position in `text`.
  return min(previous_row)


def find_best_station_matches(query: str, station_names: list[str], *, max_relative_distance: float = 0.4) -> list[str]:
  """Return the station names whose normalized text contains the closest match for `query`.

  Returns every name tied for the best distance, or an empty list if the best match is too
  far from `query` to be a plausible typo/variant.
  """

  normalized_query = normalize(query)

  if not normalized_query:
    return []

  scored = [
    (substring_distance(normalized_query, normalize(name)), name)
    for name in station_names
  ]

  best_distance = min(distance for distance, _ in scored)
  threshold = max(2, round(len(normalized_query) * max_relative_distance))

  if best_distance > threshold:
    return []

  return [name for distance, name in scored if distance == best_distance]
