"""Bounded structural PDF inspection; no rendering, execution or external programs."""

import io

from pypdf import PdfReader, apply_configuration
from pypdf.errors import LimitReachedError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    IndirectObject,
    StreamObject,
    TextStringObject,
)

MAX_PDF_OBJECTS = 5000
MAX_PDF_DEPTH = 40
MAX_DECODED_BYTES = 20 * 1024 * 1024
ACTIVE_KEYS = {
    "/JS",
    "/JavaScript",
    "/OpenAction",
    "/AA",
    "/EmbeddedFiles",
    "/XFA",
    "/RichMedia",
}
ACTIVE_ACTIONS = {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToR", "/Rendition"}


def inspect_pdf(inspector, data):
    """Resolve referenced objects, including compressed ones, within parser/worker limits."""
    try:
        with apply_configuration(
            maximum_declared_stream_length=MAX_DECODED_BYTES,
            array_maximum_element_count=MAX_PDF_OBJECTS,
            dictionary_maximum_element_count=MAX_PDF_OBJECTS,
            array_based_stream_maximum_output_length=MAX_DECODED_BYTES,
            zlib_maximum_output_length=MAX_DECODED_BYTES,
            lzw_maximum_output_length=MAX_DECODED_BYTES,
            run_length_maximum_output_length=MAX_DECODED_BYTES,
            brotli_maximum_output_length=MAX_DECODED_BYTES,
            stream_decoding_work_maximum_length=MAX_DECODED_BYTES,
            stream_filters_maximum_length=8,
            page_tree_maximum_entries=MAX_PDF_OBJECTS,
            jbig2dec_binary=None,
        ):
            reader = PdfReader(io.BytesIO(data), strict=True)
            if reader.is_encrypted:
                inspector.finding(
                    "PDF cifrado: no se inspeccionó su contenido.",
                    incomplete=True,
                    reason="pdf_encrypted",
                )
                return
            stack = [(reader.root_object, 0)]
            seen = set()
            decoded_bytes = 0
            visited = 0
            while stack:
                value, depth = stack.pop()
                visited += 1
                if visited > MAX_PDF_OBJECTS or depth > MAX_PDF_DEPTH:
                    inspector.finding(
                        "Se alcanzó el límite de objetos o profundidad del PDF.",
                        incomplete=True,
                        reason="pdf_object_limit",
                    )
                    return
                if isinstance(value, IndirectObject):
                    identity = (value.idnum, value.generation)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    value = value.get_object()
                if isinstance(value, DictionaryObject):
                    if (
                        ACTIVE_KEYS.intersection(value)
                        or value.get("/S") in ACTIVE_ACTIONS
                        or value.get("/Type") == "/EmbeddedFile"
                    ):
                        inspector.finding(
                            "PDF con acciones activas, formularios activos o archivos embebidos.",
                            suspicious=True,
                        )
                    if len(stack) + len(value) > MAX_PDF_OBJECTS:
                        inspector.finding(
                            "Se alcanzó el límite de objetos del PDF.",
                            incomplete=True,
                            reason="pdf_object_limit",
                        )
                        return
                    stack.extend((child, depth + 1) for child in value.values())
                    if isinstance(value, StreamObject) and value.get("/Subtype") != "/Image":
                        content = value.get_data()
                        decoded_bytes += len(content)
                        if decoded_bytes > MAX_DECODED_BYTES:
                            inspector.finding(
                                "Se alcanzó el límite de descompresión del PDF.",
                                incomplete=True,
                                reason="pdf_expansion_limit",
                            )
                            return
                        inspector.indicators(content)
                elif isinstance(value, ArrayObject):
                    if len(stack) + len(value) > MAX_PDF_OBJECTS:
                        inspector.finding(
                            "Se alcanzó el límite de objetos del PDF.",
                            incomplete=True,
                            reason="pdf_object_limit",
                        )
                        return
                    stack.extend((child, depth + 1) for child in value)
                elif isinstance(value, (TextStringObject, ByteStringObject)):
                    inspector.indicators(
                        value.encode("utf-8") if isinstance(value, str) else bytes(value)
                    )
            inspector.finding(
                "Estructura PDF inspeccionada sin ejecutar acciones ni renderizar imágenes."
            )
    except LimitReachedError:
        inspector.finding(
            "Se alcanzó un límite de recursos del analizador PDF.",
            incomplete=True,
            reason="pdf_resource_limit",
        )
    except Exception:
        # Untrusted parsers can fail in different ways. Never interpret failure as no detections.
        inspector.finding(
            "No fue posible completar la inspección estructural del PDF.",
            incomplete=True,
            reason="pdf_parse_failed",
        )
