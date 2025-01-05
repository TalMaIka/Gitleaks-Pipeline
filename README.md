# Gitleaks-Pipeline

This project provides a Python-based Docker pipeline to run [Gitleaks](https://github.com/zricethezav/gitleaks), a tool for detecting sensitive information (e.g., secrets, API keys, passwords) in your git repositories. It simplifies the process of running Gitleaks within a Docker container, and includes a Python script for automating the build and run of the Docker container, as well as processing the output.

## Project Structure

The project is structured as follows:

```
gitleaks-pipeline/
│
├── src/                    # Source folder for Docker and Python code
│   ├── Dockerfile          # Dockerfile to build the image
│   ├── requirements.txt    # Python dependencies (e.g., pydantic)
│   ├── transform_results.py # Python script to run Gitleaks and process output
│   └── gitleaks.toml       # Configuration for Gitleaks
│
├── tests/                  # Test directory
│   ├── api-keys.txt        # API keys for testing (if applicable)
│   └── test_transform_results.py # Test file for `transform_results.py`
│
├── sandbox.py              # Main Python script to automate Docker build and run gitleaks the pipeline
└── README.md               # Instructions on building and running the Docker image
```

## Getting Started

To get started with this project, you have two options: running it manually using Docker commands, or using the provided `sandbox.py` Python script to automate the process.

### Option 1: Using `sandbox.py` Script

The `sandbox.py` script automates the Docker container build and run process. It allows you to pass various flags to Gitleaks for more control over its execution.
For enhanced verbosity, you can use the `-v` or `--verbose` flag.

1. **Ensure you have Docker installed**. If you don't have it installed, please follow the instructions at https://docs.docker.com/get-docker/.

2. **Run the `sandbox.py` script**:
   ```bash
   python3 sandbox.py --verbose detect --no-git
   ```

   This command will:
   - Build the Docker image if not exists.
   - Run Gitleaks with the provided arguments.
   - Print logs during the process.

### Option 2: Manually Building and Running the Docker Image

If you prefer to manually build and run the Docker container, you can use the following commands.

1. **Build the Docker image**:
   ```bash
   docker build -t gitleaks-pipeline -f src/Dockerfile .
   ```

2. **Run the Docker container** with the desired Gitleaks command:
   ```bash
   docker run --rm -v $(pwd):/code/ gitleaks-pipeline detect --no-git
   ```

   This will:
   - Build and tag the Docker image as `gitleaks-pipeline`.
   - Mount the current directory (`$(pwd)`) to the `/code/` directory inside the container.
   - Run the Gitleaks tool to detect sensitive data without git integration.

## Configuration

The `gitleaks.toml` file located in the `src/` folder is used to configure Gitleaks' scanning rules. You can modify this file to customize the rules for detecting secrets based on your project's needs. 

## Output

After Gitleaks completes its scan, the output will be saved in a JSON format. The default output filename is `report_<Timestamp>.json`, which will processed to the desired structure named `transformed_report_<Timestamp>.json`

### Example Error Structure

In case of errors (e.g., invalid Gitleaks flags or commands), the errors will be captured in a structured format. Here's an example of the structure for generated errors:

```json
{
    "exit_code": 2,
    "error_message": "Error: unknown flag: --no-gi"
}
```

This structure includes:
- `exit_code`: The exit code of the process, where a non-zero value indicates an error (e.g., `2` for command-related issues).
- `error_message`: The actual error message generated by the Gitleaks tool, explaining the issue (e.g., an unknown flag or incorrect command).

### Example Report

An example of the report is provided in `example_report.json`. This file contains a list of findings, including file paths, line numbers, and descriptions of the detected sensitive data.

## Tests

### 1. Install Dependencies

Use `pip` to install the required dependencies for the project, including `pytest` for testing:

```bash
cd tests

pip install -r requirements.txt
```

This will install all the dependencies, including `pytest`.

### 2. Running the Tests

You can now run the tests using `pytest`. Specifically, to run the tests in `test_transform_results.py`, use the following command:

```bash
pytest tests/test_transform_results.py
```

If there's an error or failure, the output will show details of which tests failed and why.
