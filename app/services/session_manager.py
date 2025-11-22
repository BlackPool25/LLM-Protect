"""
Session management service for conversation memory.

Maintains conversation history across multiple requests, enabling context-aware
responses like ChatGPT. Sessions are stored in-memory with automatic cleanup.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from threading import Lock
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ConversationMessage:
    """Represents a single message in a conversation."""
    
    def __init__(self, role: str, content: str, timestamp: Optional[float] = None):
        """
        Initialize a conversation message.
        
        Args:
            role: Message role ('user' or 'assistant')
            content: Message content
            timestamp: Unix timestamp (auto-generated if not provided)
        """
        self.role = role
        self.content = content
        self.timestamp = timestamp or time.time()
    
    def to_dict(self) -> Dict:
        """Convert message to dictionary."""
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp
        }
    
    def age_seconds(self) -> float:
        """Get age of message in seconds."""
        return time.time() - self.timestamp


class ConversationSession:
    """Represents a conversation session with history."""
    
    def __init__(self, session_id: str):
        """
        Initialize a conversation session.
        
        Args:
            session_id: Unique session identifier
        """
        self.session_id = session_id
        self.messages: List[ConversationMessage] = []
        self.created_at = time.time()
        self.last_access = time.time()
    
    def add_message(self, role: str, content: str):
        """
        Add a message to the conversation.
        
        Args:
            role: Message role ('user' or 'assistant')
            content: Message content
        """
        message = ConversationMessage(role, content)
        self.messages.append(message)
        self.last_access = time.time()
        logger.debug(f"Added {role} message to session {self.session_id[:8]}")
    
    def get_messages(self, limit: Optional[int] = None) -> List[ConversationMessage]:
        """
        Get conversation messages.
        
        Args:
            limit: Maximum number of recent messages to return
        
        Returns:
            List of conversation messages
        """
        self.last_access = time.time()
        if limit:
            return self.messages[-limit:]
        return self.messages
    
    def get_formatted_history(self, limit: Optional[int] = None) -> str:
        """
        Get conversation history as formatted string.
        
        Args:
            limit: Maximum number of recent messages to return
        
        Returns:
            Formatted conversation history
        """
        messages = self.get_messages(limit)
        
        if not messages:
            return ""
        
        lines = []
        for msg in messages:
            role_label = "User" if msg.role == "user" else "Assistant"
            lines.append(f"{role_label}: {msg.content}")
        
        return "\n".join(lines)
    
    def clear(self):
        """Clear all messages in the session."""
        self.messages = []
        self.last_access = time.time()
        logger.info(f"Cleared session {self.session_id[:8]}")
    
    def get_message_count(self) -> int:
        """Get number of messages in session."""
        return len(self.messages)
    
    def inactive_seconds(self) -> float:
        """Get seconds since last activity."""
        return time.time() - self.last_access
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "message_count": len(self.messages),
            "messages": [msg.to_dict() for msg in self.messages],
            "created_at": self.created_at,
            "last_access": self.last_access,
            "inactive_seconds": self.inactive_seconds()
        }


class SessionManager:
    """
    Manages conversation sessions with automatic cleanup.
    
    Features:
    - In-memory session storage
    - Automatic cleanup of expired sessions
    - Thread-safe operations
    - Configurable history limits
    - Session statistics
    """
    
    def __init__(
        self,
        max_inactive_minutes: int = 60,
        max_messages_per_session: int = 20,
        cleanup_interval_seconds: int = 300
    ):
        """
        Initialize session manager.
        
        Args:
            max_inactive_minutes: Minutes before session expires
            max_messages_per_session: Maximum messages to keep per session
            cleanup_interval_seconds: Seconds between automatic cleanups
        """
        self.sessions: Dict[str, ConversationSession] = {}
        self.max_inactive_seconds = max_inactive_minutes * 60
        self.max_messages_per_session = max_messages_per_session
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.last_cleanup = time.time()
        self.lock = Lock()
        
        logger.info(
            f"SessionManager initialized: "
            f"max_inactive={max_inactive_minutes}min, "
            f"max_messages={max_messages_per_session}"
        )
    
    def create_session(self) -> str:
        """
        Create a new conversation session.
        
        Returns:
            New session ID
        """
        with self.lock:
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = ConversationSession(session_id)
            logger.info(f"Created session: {session_id[:8]}...")
            self._cleanup_if_needed()
            return session_id
    
    def get_session(self, session_id: str) -> Optional[ConversationSession]:
        """
        Get a session by ID.
        
        Args:
            session_id: Session identifier
        
        Returns:
            ConversationSession or None if not found
        """
        with self.lock:
            self._cleanup_if_needed()
            return self.sessions.get(session_id)
    
    def add_message(self, session_id: str, role: str, content: str) -> bool:
        """
        Add a message to a session.
        
        Args:
            session_id: Session identifier
            role: Message role ('user' or 'assistant')
            content: Message content
        
        Returns:
            True if successful, False if session not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found: {session_id[:8]}...")
                return False
            
            session.add_message(role, content)
            
            # Trim old messages if exceeding limit
            if len(session.messages) > self.max_messages_per_session:
                removed = len(session.messages) - self.max_messages_per_session
                session.messages = session.messages[-self.max_messages_per_session:]
                logger.debug(f"Trimmed {removed} old messages from session {session_id[:8]}")
            
            return True
    
    def get_context(
        self,
        session_id: str,
        limit: Optional[int] = None,
        formatted: bool = False
    ) -> Optional[List[ConversationMessage] | str]:
        """
        Get conversation context for a session.
        
        Args:
            session_id: Session identifier
            limit: Maximum number of recent messages
            formatted: Return as formatted string instead of message list
        
        Returns:
            List of messages, formatted string, or None if session not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            if formatted:
                return session.get_formatted_history(limit)
            else:
                return session.get_messages(limit)
    
    def clear_session(self, session_id: str) -> bool:
        """
        Clear all messages in a session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            True if successful, False if session not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            session.clear()
            return True
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session completely.
        
        Args:
            session_id: Session identifier
        
        Returns:
            True if deleted, False if not found
        """
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                logger.info(f"Deleted session: {session_id[:8]}...")
                return True
            return False
    
    def _cleanup_if_needed(self):
        """Clean up expired sessions if cleanup interval has passed."""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval_seconds:
            return
        
        self._cleanup_expired_sessions()
        self.last_cleanup = now
    
    def _cleanup_expired_sessions(self):
        """Remove sessions that have been inactive too long."""
        now = time.time()
        expired = []
        
        for session_id, session in self.sessions.items():
            if session.inactive_seconds() > self.max_inactive_seconds:
                expired.append(session_id)
        
        for session_id in expired:
            del self.sessions[session_id]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
    
    def cleanup_all_expired(self):
        """Force cleanup of all expired sessions."""
        with self.lock:
            self._cleanup_expired_sessions()
    
    def get_stats(self) -> Dict:
        """
        Get statistics about active sessions.
        
        Returns:
            Dictionary with session statistics
        """
        with self.lock:
            total_sessions = len(self.sessions)
            total_messages = sum(s.get_message_count() for s in self.sessions.values())
            
            if total_sessions > 0:
                avg_messages = total_messages / total_sessions
                oldest_session = min(s.created_at for s in self.sessions.values())
                newest_session = max(s.created_at for s in self.sessions.values())
            else:
                avg_messages = 0
                oldest_session = None
                newest_session = None
            
            return {
                "total_sessions": total_sessions,
                "total_messages": total_messages,
                "average_messages_per_session": round(avg_messages, 2),
                "oldest_session_age_seconds": time.time() - oldest_session if oldest_session else 0,
                "newest_session_age_seconds": time.time() - newest_session if newest_session else 0,
                "max_inactive_seconds": self.max_inactive_seconds,
                "max_messages_per_session": self.max_messages_per_session
            }
    
    def list_sessions(self) -> List[Dict]:
        """
        List all active sessions with details.
        
        Returns:
            List of session dictionaries
        """
        with self.lock:
            return [session.to_dict() for session in self.sessions.values()]


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """
    Get or create the global SessionManager instance.
    
    Returns:
        Global SessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager(
            max_inactive_minutes=60,  # 1 hour
            max_messages_per_session=20,  # Keep last 20 messages
            cleanup_interval_seconds=300  # Cleanup every 5 minutes
        )
    return _session_manager


def format_conversation_for_rag(messages: List[ConversationMessage], max_messages: int = 5) -> str:
    """
    Format conversation history for use as RAG context.
    
    Args:
        messages: List of conversation messages
        max_messages: Maximum recent messages to include
    
    Returns:
        Formatted conversation history
    """
    recent_messages = messages[-max_messages:] if len(messages) > max_messages else messages
    
    if not recent_messages:
        return ""
    
    lines = ["Previous conversation context:"]
    for msg in recent_messages:
        role = "User" if msg.role == "user" else "Assistant"
        lines.append(f"{role}: {msg.content}")
    
    return "\n".join(lines)

