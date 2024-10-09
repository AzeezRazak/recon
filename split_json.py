import json
import tiktoken  # OpenAI's tokenizer library

# Load JSON and count tokens
def count_tokens(file_path, model="gpt-4"):
    # Load JSON data
    with open(file_path, 'r') as file:
        data = json.load(file)

    # Convert JSON to string
    json_string = json.dumps(data)

    # Tokenize using OpenAI's tiktoken library
    encoding = tiktoken.encoding_for_model(model)
    tokens = encoding.encode(json_string)

    # Print the token count
    print(f"Number of tokens: {len(tokens)}")

# Example usage
count_tokens('your_file.json')
