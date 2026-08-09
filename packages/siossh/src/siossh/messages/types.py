from typing import Annotated

from ..encoding import EncodingAnnotation


type LanguageTag = Annotated[str, EncodingAnnotation('name')]
