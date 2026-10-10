"""posta: programmable mailbox hosting. https://posta.preved.co/docs"""
from .client import Posta, PostaError
from .inbox import Inbox, Message
from .webhook import verify_webhook

__all__ = ["Posta", "PostaError", "Inbox", "Message", "verify_webhook"]
__version__ = "0.1.0"
