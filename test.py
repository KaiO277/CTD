import re
import difflib

# Define the token specifications using regular expressions
token_specs = [
    ('KEYWORD', r'\b(void|int|for|while|if|else|return|break|continue|main)\b'),  # Keywords
    ('ID', r'[A-Za-z_][A-Za-z0-9_]*'),  # Identifiers
    ('NUM', r'\b\d+(\.\d*)?([eE][+-]?\d+)?\b|\.\d+([eE][+-]?\d+)?'),  # Numbers
    ('STRING', r'"([^"\\]*(\\.[^"\\]*)*)?"'),  # Strings
    ('ASSIGN', r'='),  # Assignment operator
    ('OP', r'[+\-*/]'),  # Arithmetic operators
    ('RELOP', r'[<>]=?|==|!='),  # Relational operators
    ('SEMI', r';'),  # Semicolon
    ('LPAREN', r'\('),  # Left parenthesis
    ('RPAREN', r'\)'),  # Right parenthesis
    ('LBRACE', r'\{'),  # Left brace
    ('RBRACE', r'\}'),  # Right brace
    ('COMMA', r','),  # Comma
    ('WHITESPACE', r'\s+'),  # Whitespace
    ('ERROR', r'.'),  # Catch-all for any error
]

# Compile all token specifications into a single regular expression
token_re = '|'.join(f'(?P<{pair[0]}>{pair[1]})' for pair in token_specs)

# Function to check for similar keywords
def check_keyword_similarity(identifier):
    keywords = ['void', 'int', 'for', 'while', 'if', 'else', 'return', 'break', 'continue', 'main']
    similar_keywords = difflib.get_close_matches(identifier, keywords, n=1, cutoff=0.8)
    if similar_keywords:
        return f"Error: Identifier '{identifier}' is too similar to keyword '{similar_keywords[0]}'."
    return None

# Lexical analyzer function
def lexical_analyzer(code):
    tokens = []
    error_flag = False  # Flag to control error detection
    expecting_type_keyword = True  # Check context when expecting type keyword
    line_number = 1  # Track the line number

    for match in re.finditer(token_re, code):
        kind = match.lastgroup
        value = match.group(kind)

        # Update line number for each newline character in the match
        line_number += value.count('\n')

        if kind == 'WHITESPACE':
            continue  # Ignore whitespace

        elif kind == 'ERROR':
            print(f"Error: Unrecognized token '{value}' at line {line_number}")
            error_flag = True
            break  # Stop analysis on error

        elif kind == 'KEYWORD':
            tokens.append((kind, value))
            if value in ['void', 'int', 'for', 'while', 'if', 'else']:
                expecting_type_keyword = False  # Expecting an ID after these keywords
            else:
                expecting_type_keyword = False
        
        elif kind == 'ID':
            if expecting_type_keyword:
                error_message = check_keyword_similarity(value)
                if error_message:
                    print(f"{error_message} at line {line_number}")
                    error_flag = True
                    break
            tokens.append((kind, value))
            expecting_type_keyword = False

        elif kind == 'NUM':
            tokens.append((kind, value))

        elif kind == 'COMMA':
            tokens.append((kind, value))

        elif kind == 'STRING':
            tokens.append((kind, value))  # Add handling for string tokens

        else:
            tokens.append((kind, value))
            expecting_type_keyword = False

    if error_flag:
        return None
    else:
        return tokens

# Function to read input file
def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

# Main function
def main():
    # Read the code from input file
    code = read_file('input_code.txt')

    # Run the lexical analyzer
    tokens = lexical_analyzer(code)

    # If no errors, print the tokens
    if tokens is not None:
        print("Class      : Lexeme")
        print("--------------------")
        for token in tokens:
            print(f'{token[0]:<10}: {token[1]}')
    else:
        print("Lexical analysis stopped due to an error.")

if __name__ == "__main__":
    main()
