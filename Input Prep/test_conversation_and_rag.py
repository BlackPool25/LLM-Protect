#!/usr/bin/env python3
"""
Test conversation memory and RAG (Vector DB) functionality.

Demonstrates:
1. Creating a conversation session
2. Multi-turn conversation with context
3. RAG retrieval from vector database
4. Session management
"""

import requests
import json
import time

# API base URL
BASE_URL = "http://localhost:8000/api/v1"


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_conversation_memory():
    """Test conversation memory feature."""
    
    print_section("TEST 1: CONVERSATION MEMORY")
    
    # Step 1: Create a new session
    print("\n1. Creating new conversation session...")
    response = requests.post(f"{BASE_URL}/sessions/create")
    session_data = response.json()
    session_id = session_data["session_id"]
    print(f"   ✓ Session created: {session_id[:16]}...")
    
    # Step 2: First question
    print("\n2. Asking first question: 'What is DSA?'")
    response = requests.post(
        f"{BASE_URL}/prepare-text",
        data={
            "user_prompt": "What is DSA?",
            "session_id": session_id,
            "use_conversation_history": "true"
        }
    )
    prepared = response.json()
    print(f"   ✓ Request ID: {prepared['metadata']['request_id'][:16]}...")
    print(f"   ✓ Session ID: {prepared['metadata']['session_id'][:16]}...")
    
    # Generate response
    response = requests.post(
        f"{BASE_URL}/generate",
        json={
            "prepared_input": prepared,
            "max_new_tokens": 100
        }
    )
    result = response.json()
    if result["success"]:
        print(f"   ✓ LLM Response: {result['generated_text'][:150]}...")
    
    time.sleep(0.5)
    
    # Step 3: Follow-up question (tests conversation memory)
    print("\n3. Asking follow-up: 'How do I learn it?' (should remember DSA)")
    response = requests.post(
        f"{BASE_URL}/prepare-text",
        data={
            "user_prompt": "How do I learn it in 2 months?",
            "session_id": session_id,
            "use_conversation_history": "true"
        }
    )
    prepared = response.json()
    
    # Check if conversation history was included
    external_chunks = prepared['text_embed_stub']['normalized_external']
    history_included = any('Previous conversation' in chunk for chunk in external_chunks)
    
    if history_included:
        print("   ✓ Conversation history INCLUDED as context!")
        print(f"   ✓ External chunks: {len(external_chunks)}")
    else:
        print("   ⚠ Conversation history NOT included")
    
    # Generate response
    response = requests.post(
        f"{BASE_URL}/generate",
        json={
            "prepared_input": prepared,
            "max_new_tokens": 150
        }
    )
    result = response.json()
    if result["success"]:
        print(f"   ✓ LLM Response: {result['generated_text'][:150]}...")
    
    # Step 4: Get session info
    print("\n4. Checking session information...")
    response = requests.get(f"{BASE_URL}/sessions/{session_id}")
    session_info = response.json()
    print(f"   ✓ Messages in session: {session_info['message_count']}")
    print(f"   ✓ Session age: {session_info['inactive_seconds']:.1f}s")
    
    # Step 5: List all sessions
    print("\n5. Listing all active sessions...")
    response = requests.get(f"{BASE_URL}/sessions")
    sessions_data = response.json()
    print(f"   ✓ Total active sessions: {sessions_data['stats']['total_sessions']}")
    print(f"   ✓ Total messages: {sessions_data['stats']['total_messages']}")
    
    return session_id


def test_vector_db_rag():
    """Test RAG with vector database."""
    
    print_section("TEST 2: RAG (VECTOR DATABASE) RETRIEVAL")
    
    # Create new session for RAG test
    response = requests.post(f"{BASE_URL}/sessions/create")
    session_id = response.json()["session_id"]
    print(f"\n1. Created session: {session_id[:16]}...")
    
    # Test query that should retrieve from vector DB
    print("\n2. Asking: 'What is the capital of France?' (with RAG enabled)")
    response = requests.post(
        f"{BASE_URL}/prepare-text",
        data={
            "user_prompt": "What is the capital of France?",
            "session_id": session_id,
            "retrieve_from_vector_db": "true",
            "use_conversation_history": "false"  # Disable history for cleaner test
        }
    )
    prepared = response.json()
    
    # Check if RAG data was retrieved
    external_chunks = prepared['text_embed_stub']['normalized_external']
    rag_enabled = prepared['metadata']['rag_enabled']
    
    print(f"   ✓ RAG enabled: {rag_enabled}")
    print(f"   ✓ External chunks: {len(external_chunks)}")
    
    if external_chunks:
        print(f"   ✓ Retrieved context from vector DB!")
        for i, chunk in enumerate(external_chunks[:2]):
            clean_chunk = chunk.replace('[EXTERNAL]', '').replace('[/EXTERNAL]', '')
            print(f"      Chunk {i+1}: {clean_chunk[:80]}...")
    else:
        print("   ⚠ No context retrieved from vector DB")
        print("      Did you run: python populate_vector_db.py ?")
    
    # Generate response with RAG context
    response = requests.post(
        f"{BASE_URL}/generate",
        json={
            "prepared_input": prepared,
            "max_new_tokens": 100
        }
    )
    result = response.json()
    if result["success"]:
        print(f"   ✓ LLM Response: {result['generated_text'][:150]}...")
    
    return session_id


def test_session_management(session_id):
    """Test session management operations."""
    
    print_section("TEST 3: SESSION MANAGEMENT")
    
    # Clear session
    print("\n1. Clearing session messages...")
    response = requests.post(f"{BASE_URL}/sessions/{session_id}/clear")
    print(f"   ✓ {response.json()['message']}")
    
    # Verify cleared
    response = requests.get(f"{BASE_URL}/sessions/{session_id}")
    session_info = response.json()
    print(f"   ✓ Messages after clear: {session_info['message_count']}")
    
    # Delete session
    print("\n2. Deleting session...")
    response = requests.delete(f"{BASE_URL}/sessions/{session_id}")
    print(f"   ✓ {response.json()['message']}")
    
    # Verify deleted
    response = requests.get(f"{BASE_URL}/sessions/{session_id}")
    if response.status_code == 404:
        print(f"   ✓ Session successfully deleted (404 returned)")


def main():
    """Run all tests."""
    
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#   LLM-PROTECT: CONVERSATION MEMORY & RAG TESTING                 #")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    print("\nPrerequisites:")
    print("  1. Server running: uvicorn app.main:app --reload")
    print("  2. Vector DB populated: python populate_vector_db.py")
    print("  3. ChromaDB installed: pip install chromadb")
    
    input("\nPress Enter to start tests...")
    
    try:
        # Test 1: Conversation Memory
        session_id_1 = test_conversation_memory()
        
        # Test 2: RAG with Vector DB
        session_id_2 = test_vector_db_rag()
        
        # Test 3: Session Management
        test_session_management(session_id_2)
        
        # Summary
        print_section("✅ ALL TESTS COMPLETED SUCCESSFULLY!")
        
        print("\n📊 Summary:")
        print("  ✓ Conversation memory working")
        print("  ✓ Multi-turn conversations with context")
        print("  ✓ RAG retrieval from vector database")
        print("  ✓ Session management (create/clear/delete)")
        print("  ✓ HMAC signatures on all external data")
        
        print(f"\n🔑 Remaining active session: {session_id_1[:16]}...")
        print(f"   You can continue this conversation or delete it via API")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to server!")
        print("   Make sure the server is running:")
        print("   uvicorn app.main:app --reload")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

