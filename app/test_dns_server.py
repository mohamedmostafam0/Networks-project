import subprocess

def test_dns_server():
    # Start the DNS server (replace 'dns_server.py' with the correct script)
    process = subprocess.Popen(
        ['python3', 'main.py'],  # Command to run the server
        stdin=subprocess.PIPE,         # Pipe for sending inputs
        stdout=subprocess.PIPE,        # Capture output
        stderr=subprocess.PIPE         # Capture error output (if any)
    )

    # Simulate typing '1' followed by 'example.com'
    process.stdin.write(b'1\n')          # Send '1' as input (e.g., for selecting a menu option)
    process.stdin.write(b'example.com\n')  # Send 'example.com' as input (domain name)
    process.stdin.flush()               # Make sure input is sent

    # Read the output from stdout
    output, error = process.communicate()  # This waits for the process to finish and captures the output

    # Print output for verification (this could be customized based on what the server outputs)
    print(f"Output:\n{output.decode()}")
    if error:
        print(f"Error:\n{error.decode()}")

    # Optionally assert expected output if you know what should happen
    # For example:
    # assert "example.com" in output.decode()  # Customize as needed for your case

if __name__ == "__main__":
    test_dns_server()
