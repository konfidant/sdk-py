class KonfidantApiError(Exception):
    def __init__(self, message: str, status_code: int, body: object) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
