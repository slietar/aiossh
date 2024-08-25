from typing import Annotated, Literal

from ..encoding import EncodingAnnotation


type LanguageTag = Annotated[Literal[''], EncodingAnnotation('name')]
