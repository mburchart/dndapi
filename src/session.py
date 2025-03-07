from user import User
from datetime import datetime
from typing import Optional

class UserSession:
    
    def __init__(self, id: int, user: User, access_token: str, refresh_token: str, token_type: str, grant_type: str, scope: str, client_id: str, client_secret: str, expires_at: datetime, created_at: datetime, last_used: Optional[datetime] = None):
        self.id = id
        self.user = user
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = token_type
        self.grant_type = grant_type
        self.scope = scope
        self.client_id = client_id
        self.client_secret = client_secret
        self.expires_at = expires_at
        self.created_at = created_at
        self.last_used = last_used

    