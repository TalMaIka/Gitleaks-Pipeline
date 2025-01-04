import os
import json
import pytest
import re
from datetime import datetime
from transform_results import (
    ReportFile,
    ExitCodes,
    transform_results,
    write_error_message
)

# Fixtures for testing
@pytest.fixture
def sample_gitleaks_report(tmp_path):
    """Fixture to create a temporary sample Gitleaks report file."""
    content = [
 {
  "Description": "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
  "StartLine": 42,
  "EndLine": 42,
  "StartColumn": 2,
  "EndColumn": 52,
  "Match": "xoxb-123456789012-123456789012-12345678901234567890",
  "Secret": "xoxb-123456789012-123456789012-12345678901234567890",
  "File": "tests/test-leak-file.txt",
  "SymlinkFile": "",
  "Commit": "",
  "Entropy": 3.6768482,
  "Author": "",
  "Email": "",
  "Date": "",
  "Message": "",
  "Tags": [],
  "RuleID": "slack-bot-token",
  "Fingerprint": "tests/test-leak-file.txt:slack-bot-token:42"
 },
 {
  "Description": "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
  "StartLine": 60,
  "EndLine": 60,
  "StartColumn": 2,
  "EndColumn": 40,
  "Match": "AIzaSyBp7x1lShBzZa66wRoj0mEGk1cews4Bftg",
  "Secret": "AIzaSyBp7x1lShBzZa66wRoj0mEGk1cews4Bftg",
  "File": "tests/test-leak-file.txt",
  "SymlinkFile": "",
  "Commit": "",
  "Entropy": 4.8557897,
  "Author": "",
  "Email": "",
  "Date": "",
  "Message": "",
  "Tags": [],
  "RuleID": "gcp-api-key",
  "Fingerprint": "tests/test-leak-file.txt:gcp-api-key:60"
 },
    ]
    file_path = tmp_path / "gitleaks_report.json"
    with open(file_path, "w") as file:
        json.dump(content, file)
    return str(file_path)

@pytest.fixture
def empty_gitleaks_report(tmp_path):
    """Fixture to create an empty Gitleaks report file."""
    file_path = tmp_path / "empty_gitleaks_report.json"
    with open(file_path, "w") as file:
        json.dump([], file)
    return str(file_path)

@pytest.fixture
def invalid_gitleaks_report(tmp_path):
    """Fixture to create an invalid (non-JSON) Gitleaks report file."""
    file_path = tmp_path / "invalid_gitleaks_report.json"
    with open(file_path, "w") as file:
        file.write("Not a JSON content")
    return str(file_path)

# Test cases
def test_generate_filename():
    """Test the generation of filenames with timestamps."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    report_file = ReportFile(base_name="test", extension=".txt", timestamp=timestamp)
    expected_filename = f"test_{timestamp}.txt"
    assert report_file.generate_filename() == expected_filename

 # Test transforming a valid Gitleaks report file.
def test_transform_results_successful(sample_gitleaks_report, tmp_path):
    # Prefix of the expected output file
    output_file_prefix = "transformed_report_"
    
    os.chdir(tmp_path)  # Ensure the test runs in the temp directory
    transform_results(sample_gitleaks_report)
    
    # Check if a file with the expected prefix exists
    files = os.listdir(tmp_path)
    
    # look for the output file named transformed_report_<Timestamp>.json
    output_file = None
    for file in files:
        if file.startswith(output_file_prefix) and file.endswith('.json'):
            output_file = file
            break
    
    assert output_file is not None, "Output file not found."
    
    timestamp_pattern = r"transformed_report_(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2})\.json"
    match = re.match(timestamp_pattern, output_file)
    assert match is not None, f"Output file name doesn't match the expected: {output_file}"

    # Optionally check if the file content is valid
    with open(output_file, "r") as file:
        content = json.load(file)
    
    assert "findings" in content
    assert len(content["findings"]) == 2
    assert content["findings"][0]["filename"] == "tests/test-leak-file.txt"

# Test handling an empty Gitleaks report.
def test_transform_results_no_findings(empty_gitleaks_report, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        transform_results(empty_gitleaks_report)
    assert excinfo.value.code == ExitCodes.NO_FINDINGS.value

# Test handling a non-existent Gitleaks report.
def test_transform_results_file_not_found(tmp_path):
    
    missing_file = tmp_path / "missing_report.json"
    output_path = tmp_path / "error_report.json"
    with pytest.raises(SystemExit) as excinfo:
        transform_results(str(missing_file))
    assert excinfo.value.code == ExitCodes.FILE_NOT_FOUND.value


# Test handling an invalid Gitleaks report.
def test_transform_results_invalid_file(invalid_gitleaks_report):
    
    with pytest.raises(json.JSONDecodeError):
        transform_results(invalid_gitleaks_report)

# Test handling an invalid structured Gitleaks report.
def test_transform_results_invalid_json_structure(tmp_path):
    
    invalid_content = "{ 'Invalid': 'Structure' }"
    invalid_file_path = tmp_path / "invalid_structure_report.json"
    with open(invalid_file_path, "w") as file:
        file.write(invalid_content)

    with pytest.raises(json.JSONDecodeError):
        transform_results(str(invalid_file_path))

# Test writing an error message to a file to invalid path.
def test_write_error_message_invalid_path(tmp_path):
    
    error_file = tmp_path / "nonexistent_folder/error.json"
    os.makedirs(tmp_path / "nonexistent_folder", exist_ok=True)  # Create the folder
    with pytest.raises(SystemExit) as excinfo:
        write_error_message("Test error", ExitCodes.COMMAND_ERROR.value, str(error_file))
    
    assert excinfo.value.code == 2  # Ensure the correct exit code

    # Verify that the error file is created in the correct path
    assert os.path.exists(error_file)

# Test the generation of filenames with invalid timestamp format.
def test_generate_filename_invalid_timestamp():
    invalid_timestamp = "invalid_timestamp_format"
    report_file = ReportFile(base_name="test", extension=".json", timestamp=invalid_timestamp)
    expected_filename = f"test_{invalid_timestamp}.json"
    assert report_file.generate_filename() == expected_filename

# Test creating a report file with an invalid extension.
def test_create_with_timestamp_invalid_extension():
    report_file = ReportFile.create_with_timestamp(base_name="test", extension=".json")
    assert report_file.extension == ".json"
    assert isinstance(report_file.timestamp, str)

    # Invalid extension passed to the method
    invalid_extension = ".noext"
    report_file_invalid = ReportFile.create_with_timestamp(base_name="test", extension=invalid_extension)
    assert report_file_invalid.extension == ".noext"

# Test writing an error message with a custom exit code.
def test_write_error_message_with_custom_exit_code(tmp_path):
    error_file = tmp_path / "custom_error.json"
    with pytest.raises(SystemExit) as excinfo:
        write_error_message("Custom error", 123, str(error_file))
    
    assert excinfo.value.code == 123

    # Verify that the error file content is written correctly.
    assert os.path.exists(error_file)
    with open(error_file, "r") as file:
        content = json.load(file)

    assert content["exit_code"] == 123
    assert content["error_message"] == "Custom error"

