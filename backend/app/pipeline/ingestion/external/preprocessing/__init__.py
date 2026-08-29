"""External preprocessing composed around approved shared pipeline utilities."""

from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ContentProcessingResult, ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import PreprocessingResult, TextPreprocessor

__all__ = ["ContentProcessingResult", "ExternalContentProcessor", "PreprocessingResult", "TextPreprocessor"]
