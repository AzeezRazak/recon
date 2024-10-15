import os

def split_domains_file(input_file, output_folder, chunk_size=50):
    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    # Read the domains from the input file
    with open(input_file, 'r') as file:
        domains = file.readlines()
    
    # Split domains into chunks of the specified size
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i:i + chunk_size]
        output_file = os.path.join(output_folder, f'domains_part_{i//chunk_size + 1}.txt')
        
        # Write each chunk to a new file
        with open(output_file, 'w') as chunk_file:
            chunk_file.writelines(chunk)
        print(f'Saved: {output_file}')

# Example usage
input_file = 'domains.txt'  # The file with all domains
output_folder = 'split_domains'  # The folder where the split files will be saved

split_domains_file(input_file, output_folder)
