#!/usr/bin/env python3
"""
Populate ChromaDB vector database with sample knowledge.

This script creates a knowledge base that can be retrieved during RAG queries.
"""

import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))


def populate_knowledge_base():
    """Populate the vector database with sample documents."""
    
    try:
        import chromadb
    except ImportError:
        print("❌ ChromaDB not installed!")
        print("   Install with: pip install chromadb")
        sys.exit(1)
    
    print("=" * 70)
    print("POPULATING VECTOR DATABASE")
    print("=" * 70)
    
    # Initialize ChromaDB client (new API)
    client = chromadb.PersistentClient(path="./chroma_db")
    
    # Delete existing collection if it exists
    try:
        client.delete_collection(name="knowledge_base")
        print("✓ Deleted existing knowledge_base collection")
    except:
        pass
    
    # Create new collection
    collection = client.create_collection(
        name="knowledge_base",
        metadata={"description": "General knowledge base for LLM-Protect"}
    )
    print("✓ Created new knowledge_base collection")
    
    # Sample documents about various topics
    documents = [
        # Programming & CS concepts
        "Data Structures and Algorithms (DSA) is the study of organizing and manipulating data efficiently. It includes arrays, linked lists, stacks, queues, trees, graphs, sorting, and searching algorithms.",
        
        "A stack is a linear data structure that follows LIFO (Last In First Out) principle. Common operations include push (add element), pop (remove element), and peek (view top element).",
        
        "Python is a high-level programming language known for its simplicity and readability. It's widely used for web development, data science, machine learning, and automation.",
        
        "Machine Learning is a subset of AI that enables systems to learn from data without explicit programming. Common types include supervised learning, unsupervised learning, and reinforcement learning.",
        
        # Study & Learning advice
        "To learn DSA effectively: Start with basic data structures, practice coding problems daily, understand time complexity, solve LeetCode problems, and focus on understanding rather than memorization.",
        
        "The best way to learn programming is through hands-on practice. Build projects, solve coding challenges, read others' code, and don't fear making mistakes.",
        
        "For entrance exam preparation: Create a study schedule, practice previous year papers, focus on weak areas, take mock tests regularly, and maintain consistency.",
        
        # General knowledge
        "Paris is the capital and largest city of France. It's known for the Eiffel Tower, Louvre Museum, and Notre-Dame Cathedral.",
        
        "The Earth orbits the Sun at an average distance of 150 million kilometers. This distance is called one Astronomical Unit (AU).",
        
        "Water boils at 100°C (212°F) at sea level. The boiling point decreases with altitude due to lower atmospheric pressure.",
        
        # Security & LLMs
        "Prompt injection is a security vulnerability where attackers manipulate LLM inputs to bypass safety measures or extract sensitive information.",
        
        "HMAC (Hash-based Message Authentication Code) ensures data integrity and authenticity using cryptographic hash functions and secret keys.",
        
        "RAG (Retrieval-Augmented Generation) enhances LLM responses by retrieving relevant documents from a knowledge base before generating answers.",
        
        # Sample conversation responses
        "When greeting, respond politely and ask how you can help. Keep responses professional and friendly.",
        
        "If asked about your capabilities, explain that you can answer questions, help with problem-solving, and provide information on various topics."
    ]
    
    # Generate IDs for documents
    ids = [f"doc_{i}" for i in range(len(documents))]
    
    # Generate metadata
    metadatas = [
        {"source": "knowledge_base", "topic": get_topic(doc), "index": i}
        for i, doc in enumerate(documents)
    ]
    
    # Add documents to collection
    collection.add(
        documents=documents,
        ids=ids,
        metadatas=metadatas
    )
    
    print(f"✓ Added {len(documents)} documents to knowledge base")
    
    # Test a sample query
    print("\n" + "-" * 70)
    print("TESTING VECTOR DB RETRIEVAL")
    print("-" * 70)
    
    test_queries = [
        "How do I learn DSA?",
        "What is a stack?",
        "What is the capital of France?"
    ]
    
    for query in test_queries:
        print(f"\nQuery: '{query}'")
        results = collection.query(
            query_texts=[query],
            n_results=2
        )
        
        if results['documents']:
            for i, doc in enumerate(results['documents'][0]):
                print(f"  Result {i+1}: {doc[:80]}...")
    
    print("\n" + "=" * 70)
    print("✅ VECTOR DATABASE POPULATED SUCCESSFULLY!")
    print("=" * 70)
    print(f"\nDatabase location: ./chroma_db/")
    print(f"Collection name: knowledge_base")
    print(f"Total documents: {len(documents)}")
    print("\nYou can now use retrieve_from_vector_db=true in your API requests!")


def get_topic(doc: str) -> str:
    """Infer topic from document content."""
    doc_lower = doc.lower()
    
    if any(word in doc_lower for word in ['dsa', 'algorithm', 'data structure', 'stack', 'array']):
        return "programming"
    elif any(word in doc_lower for word in ['learn', 'study', 'practice', 'exam']):
        return "education"
    elif any(word in doc_lower for word in ['python', 'machine learning', 'code']):
        return "programming"
    elif any(word in doc_lower for word in ['security', 'injection', 'hmac', 'rag']):
        return "security"
    elif any(word in doc_lower for word in ['paris', 'earth', 'water', 'capital']):
        return "general_knowledge"
    else:
        return "general"


if __name__ == "__main__":
    try:
        populate_knowledge_base()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

