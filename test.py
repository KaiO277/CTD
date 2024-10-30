import re
import difflib

token_specs = [
    ('KEYWORD', r'\b(void|int|for|while|if|else|return|break|continue|main)\b'),
    ('ID', r'[A-Za-z_][A-Za-z0-9_]*'),
    ('NUM', r'\b\d+(\.\d*)?([eE][+-]?\d+)?\b|\.\d+([eE][+-]?\d+)?'),
    ('STRING', r'"([^"\\]*(\\.[^"\\]*)*)?"'),
    ('ASSIGN', r'='),
    ('OP', r'[+\-*/]'),
    ('RELOP', r'[<>]=?|==|!='),
    ('SEMI', r';'),
    ('LPAREN', r'\('),  
    ('RPAREN', r'\)'),
    ('LBRACE', r'\{'),
    ('RBRACE', r'\}'),
    ('COMMA', r','),
    ('WHITESPACE', r'\s+'),
    ('ERROR', r'.'),
]

token_re = '|'.join(f'(?P<{pair[0]}>{pair[1]})' for pair in token_specs)

def check_keyword_similarity(identifier):
    keywords = ['void', 'int', 'for', 'while', 'if', 'else', 'return', 'break', 'continue', 'main']
    similar_keywords = difflib.get_close_matches(identifier, keywords, n=1, cutoff=0.8)
    if similar_keywords:
        return f"Error: Identifier '{identifier}' is too similar to keyword '{similar_keywords[0]}'."
    return None

def lexical_analyzer(code):
    tokens = []
    error_flag = False
    expecting_type_keyword = True
    line_number = 1

    for match in re.finditer(token_re, code):
        kind = match.lastgroup
        value = match.group(kind)

        line_number += value.count('\n')

        if kind == 'WHITESPACE':
            continue

        elif kind == 'ERROR':
            print(f"Error: Unrecognized token '{value}' at line {line_number}")
            error_flag = True
            break

        elif kind == 'KEYWORD':
            tokens.append((kind, value))
            if value in ['void', 'int', 'for', 'while', 'if', 'else']:
                expecting_type_keyword = False
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
            tokens.append((kind, value))

        else:
            tokens.append((kind, value))
            expecting_type_keyword = False

    if error_flag:
        return None
    else:
        return tokens

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def main():
    code = read_file('input_code.txt')

    tokens = lexical_analyzer(code)

    if tokens is not None:
        print("Class      : Lexeme")
        print("--------------------")
        for token in tokens:
            print(f'{token[0]:<10}: {token[1]}')
    else:
        print("Lexical analysis stopped due to an error.")

if __name__ == "__main__":
    main()
