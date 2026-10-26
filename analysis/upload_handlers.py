from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.core.files.uploadhandler import FileUploadHandler, StopUpload


class BoundedUploadHandler(FileUploadHandler):
    """Enforce limits while streaming, before temporary-file storage."""

    def handle_raw_input(self, input_data, META, content_length, boundary, encoding=None):
        self.total = 0
        if content_length and content_length > settings.MAX_UPLOAD_BYTES + 1024 * 1024:
            raise RequestDataTooBig("Carga demasiado grande")

    def receive_data_chunk(self, raw_data, start):
        self.total += len(raw_data)
        if self.total > settings.MAX_UPLOAD_BYTES:
            raise StopUpload(connection_reset=True)
        return raw_data

    def file_complete(self, file_size):
        return None
