"""
Tests for code detection functionality in Layer0.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    detect_code,
    CodeDetectionResult,
    CODE_PATTERNS,
    HEURISTIC_PATTERNS,
)


class TestDetectCode:
    """Test suite for detect_code function."""
    
    def test_detect_python_code(self):
        """Test Python code detection."""
        text = """
Here is some Python code:
```python
def hello_world():
    print("Hello, World!")

class MyClass:
    def __init__(self):
        pass

for i in range(10):
    print(i)
```
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "python"
        assert result.confidence >= 0.35
        assert len(result.code_snippets) > 0
    
    def test_detect_c_code(self):
        """Test C/C++ code detection."""
        text = """
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Hello, World!\\n");
    return 0;
}
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "c_cpp"
        assert result.confidence >= 0.35
    
    def test_detect_java_code(self):
        """Test Java code detection."""
        text = """
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "java"
    
    def test_detect_javascript_code(self):
        """Test JavaScript code detection."""
        text = """
function greet(name) {
    console.log(`Hello, ${name}!`);
}

const add = (a, b) => {
    return a + b;
};
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "javascript"
    
    def test_detect_bash_code(self):
        """Test Bash script detection."""
        text = """
#!/bin/bash

sudo apt-get update
chmod 755 script.sh
echo "Done!"
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "bash"
    
    def test_detect_go_code(self):
        """Test Go code detection."""
        text = """
package main

import (
    "fmt"
)

func main() {
    fmt.Println("Hello, World!")
}
        """
        result = detect_code(text)
        
        assert result.is_code is True
        assert result.detected_language == "go"
    
    def test_no_code_in_plain_text(self):
        """Test that plain text is not detected as code."""
        text = """
Hello, this is just a regular message about the weather.
Today it will be sunny with temperatures around 25 degrees.
Have a great day!
        """
        result = detect_code(text)
        
        assert result.is_code is False
        assert result.detected_language is None
        assert result.confidence < 0.35
    
    def test_fenced_code_block_extraction(self):
        """Test extraction of fenced code blocks."""
        text = """
Here is an example:
```python
x = 1
y = 2
print(x + y)
```
And another:
```javascript
console.log('test');
```
        """
        result = detect_code(text)
        
        assert result.is_code is True
        # Should have at least the 2 fenced blocks
        assert len(result.code_snippets) >= 2
    
    def test_empty_text(self):
        """Test empty text handling."""
        result = detect_code("")
        
        assert result.is_code is False
        assert result.detected_language is None
        assert result.confidence == 0.0
        assert result.code_snippets == []
    
    def test_none_text(self):
        """Test None handling."""
        result = detect_code(None)  # type: ignore
        
        assert result.is_code is False
    
    def test_confidence_range(self):
        """Test that confidence is always between 0 and 1."""
        texts = [
            "",
            "Hello world",
            "def foo(): pass",
            "```python\nprint('hello')\n```" * 10,
        ]
        
        for text in texts:
            result = detect_code(text)
            assert 0.0 <= result.confidence <= 1.0
    
    def test_code_snippets_limit(self):
        """Test that code snippets are limited to 10."""
        blocks = "\n".join([f"```\ncode{i}\n```" for i in range(20)])
        result = detect_code(blocks)
        
        assert len(result.code_snippets) <= 10


class TestCodePatterns:
    """Test that code patterns compile and match correctly."""
    
    def test_python_pattern(self):
        """Test Python pattern matching."""
        pattern = CODE_PATTERNS["python"]
        
        assert pattern.search("def function():") is not None
        assert pattern.search("class MyClass:") is not None
        assert pattern.search("import os") is not None
        assert pattern.search("print('hello')") is not None
    
    def test_c_cpp_pattern(self):
        """Test C/C++ pattern matching."""
        pattern = CODE_PATTERNS["c_cpp"]
        
        assert pattern.search("#include <stdio.h>") is not None
        assert pattern.search("int main()") is not None
        assert pattern.search("printf(\"hello\")") is not None
    
    def test_java_pattern(self):
        """Test Java pattern matching."""
        pattern = CODE_PATTERNS["java"]
        
        assert pattern.search("public class Main") is not None
        assert pattern.search("System.out.println") is not None
    
    def test_javascript_pattern(self):
        """Test JavaScript pattern matching."""
        pattern = CODE_PATTERNS["javascript"]
        
        assert pattern.search("console.log('hi')") is not None
        assert pattern.search("function test()") is not None
        assert pattern.search("const x = () => {") is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
