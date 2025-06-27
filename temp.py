#!/usr/bin/env python3
"""
Script to combine all files in a directory into a single markdown file
with file name headers and appropriate code block formatting.
"""

import os
import sys
from pathlib import Path


def get_file_extension_for_markdown(file_path):
    """Get the appropriate language identifier for markdown code blocks."""
    ext = file_path.suffix.lower()
    
    # Map common extensions to markdown language identifiers
    extension_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.sh': 'bash',
        '.sql': 'sql',
        '.json': 'json',
        '.xml': 'xml',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.md': 'markdown',
        '.txt': 'text',
    }
    
    return extension_map.get(ext, 'text')


def should_include_file(file_path, exclude_patterns=None):
    """Check if file should be included based on exclusion patterns."""
    if exclude_patterns is None:
        exclude_patterns = [
            '.git', '__pycache__', '.DS_Store', 'node_modules',
            '.pyc', '.exe', '.bin', '.jpg', '.png', '.gif', '.pdf'
        ]
    
    file_name = file_path.name
    return not any(pattern in file_name for pattern in exclude_patterns)


def combine_files_to_markdown(
    directory_path, 
    output_file='combined_files.md', 
    exclude_patterns=None
):
    """
    Combine all files in a directory into a single markdown file.
    
    Args:
        directory_path (str): Path to the directory containing files
        output_file (str): Name of the output markdown file
        exclude_patterns (list): List of patterns to exclude from processing
    """
    
    directory = Path(directory_path)
    
    if not directory.exists() or not directory.is_dir():
        print(f"Error: '{directory_path}' is not a valid directory")
        return False
    
    output_path = Path(output_file)
    files_processed = 0
    
    try:
        with open(output_path, 'w', encoding='utf-8') as md_file:
            # Write header
            md_file.write(f"# Combined Files from {directory.name}\n\n")
            md_file.write(f"Generated on: {Path.cwd()}\n\n")
            md_file.write("---\n\n")
            
            # Process all files in directory
            for file_path in sorted(directory.rglob('*')):
                if (file_path.is_file() and 
                    file_path != output_path and 
                    should_include_file(file_path, exclude_patterns)):
                    
                    try:
                        # Get relative path for cleaner display
                        relative_path = file_path.relative_to(directory)
                        
                        # Write file header
                        md_file.write(f"## File: `{relative_path}`\n\n")
                        
                        # Try to read file content
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                        except UnicodeDecodeError:
                            # Handle binary files
                            md_file.write("*Binary file - content not displayed*\n\n")
                            md_file.write("---\n\n")
                            continue
                        
                        # Get appropriate language for syntax highlighting
                        language = get_file_extension_for_markdown(file_path)
                        
                        # Write content in code block
                        md_file.write(f"```{language}\n")
                        md_file.write(content)
                        if not content.endswith('\n'):
                            md_file.write('\n')
                        md_file.write("```\n\n")
                        md_file.write("---\n\n")
                        
                        files_processed += 1
                        
                    except Exception as e:
                        md_file.write(f"*Error reading file: {e}*\n\n")
                        md_file.write("---\n\n")
        
        print(f"Successfully combined {files_processed} files into '{output_file}'")
        return True
        
    except Exception as e:
        print(f"Error creating markdown file: {e}")
        return False


def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2:
        print("Usage: python combine_files.py <directory_path> [output_file.md]")
        print("Example: python combine_files.py ./src combined_source.md")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'combined_files.md'
    
    # Optional: customize exclusion patterns
    exclude_patterns = [
        '.git', '__pycache__', '.DS_Store', 'node_modules',
        '.pyc', '.exe', '.bin', '.jpg', '.png', '.gif', '.pdf',
        '.zip', '.tar', '.gz'
    ]
    
    success = combine_files_to_markdown(directory_path, output_file, exclude_patterns)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()