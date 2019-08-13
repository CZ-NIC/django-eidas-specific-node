"""Various utility functions."""
from datetime import datetime


def parse_eidas_timestamp(timestamp: str) -> datetime:
    """Parse a date & time string in eIDAS format."""
    return datetime.strptime(timestamp + '000', '%Y-%m-%d %H:%M:%S %f')


def create_eidas_timestamp(timestamp: datetime) -> str:
    """Create a date & time string in eIDAS format."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S %f")[:-3]
