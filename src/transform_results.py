import os
import sys
import subprocess
import json
from datetime import datetime
from pydantic import BaseModel
from typing import List
from enum import Enum

class ExitCodes(Enum):
    SUCCESS = 0
    ARGUMENT_OR_FLAG_ERROR = 1
    COMMAND_ERROR = 2
    FILE_NOT_FOUND = 3
    NO_FINDINGS = 4
    NO_GIT_FOLDER = 5


class ReportFile(BaseModel):
    base_name: str = "report"
    extension: str = ".json"
    timestamp: str

# Generates the report filename using the base_name, extension, and timestamp.
    def generate_filename(self) -> str:
        return f"{self.base_name}_{self.timestamp}{self.extension}"

# Creates the ReportFile with the current timestamp.
    @classmethod
    def create_with_timestamp(cls, base_name: str = "report", extension: str = ".json") -> "ReportFile":
        """Create a ReportFile instance with the current timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        return cls(base_name=base_name, extension=extension, timestamp=timestamp)

class GitleaksResultItem(BaseModel):
    filename: str
    line_range: str
    description: str


class GitleaksResults(BaseModel):
    findings: List[GitleaksResultItem]

def run_gitleaks(command_args, report_file):
    try:
        # Execute the Gitleaks command and capture the output
        subprocess.run(command_args, check=True, capture_output=True, text=True)

    except subprocess.CalledProcessError as e:
        # Capture error message from stderr
        error_message = e.stderr.strip()

        # Get the part before the first newline
        error_message = error_message.split('\n')[0]

        #Checks for any of the following keywords in the error message that's related to Gitleaks arguments 
        if any(keyword in error_message for keyword in ["unknown flag:", "flag needs an argument:"]):
            write_error_message(error_message, ExitCodes.COMMAND_ERROR.value, report_file)

        if any(keyword in error_message for keyword in ["unknown command", "for more information about a command."]):
            write_error_message(error_message, ExitCodes.ARGUMENT_OR_FLAG_ERROR.value, report_file)

        if "could not create Git cmd" in e.stderr:
            write_error_message("No .git folder found. Ensure you are in the root directory of the repository or add the flag '--no-git'", ExitCodes.NO_GIT_FOLDER.value, report_file)
        
        if "--verbose" in sys.argv or "-v" in sys.argv:
            # Print the Gitleaks output to the console
            sys.stderr.write(e.stderr)


# Converting raw output by Gitleaks output into the shorter JSON format.
def transform_results(report_path):
    if not os.path.exists(report_path):
        write_error_message("Gitleaks report file not found", ExitCodes.FILE_NOT_FOUND.value, report_path)

    with open(report_path, 'r') as file:
        gitleaks_output = json.load(file)

    findings = [
        {
            "filename": item.get("File", "unknown"),
            "line_range": f"{item.get('StartLine', 'unknown')}-{item.get('EndLine', 'unknown')}",
            "description": item.get("Description", "No description provided")
        }
        for item in gitleaks_output
    ]

    #Checks if the findings list is empty
    if not findings:
        write_error_message("No findings detected. Ensure all repository files are correctly placed in your project's main directory for accurate scanning!", ExitCodes.NO_FINDINGS.value, report_path)

    result = GitleaksResults(findings=findings)
    print(json.dumps(result.model_dump(), indent=4)) 

    # Create a new report file for the transformed results
    report_file = ReportFile.create_with_timestamp(base_name="transformed_report", extension=".json")
    transformed_report_file = report_file.generate_filename()

    # Write the transformed results to the report file
    with open(transformed_report_file, 'w') as file:
        json.dump(result.model_dump(), file, indent=4)


# Error handling for the user-provided arguments.
def write_error_message(error_message, error_code, report_file):
    try:
        with open(report_file, 'w') as file:
            json.dump({"exit_code": error_code, "error_message": error_message}, file, indent=4)
    except Exception as e:
        print(f"Error writing to output file: {e}")
        sys.exit(error_code)
    print(f"[!] Please check the output file for more details: {report_file}")
    sys.exit(error_code)


# Argument check for the user-provided run command.
def check_args(report_file):

    # No arguments provided
    if len(sys.argv) < 2:
        write_error_message(
        "Usage: docker run --rm -v $(pwd):/code gitleaks-pipeline <gitleaks-args>\n"
        "Example: docker run --rm -v $(pwd):/code/ gitleaks-pipeline detect --no-git",
        ExitCodes.COMMAND_ERROR.value, report_file)

    # Run Gitleaks help command
    if "--help" in sys.argv or "-h" in sys.argv:
        subprocess.run(["gitleaks", "--help"])
        sys.exit(0)

    # Check for --report-path flag
    if "--report-path" not in sys.argv:
        sys.argv.extend(["--report-path", report_file])   

    if "--config" in sys.argv:
        # Append the default included config file
        sys.argv.extend(["--config", "src/gitleaks.toml"])

    if "gitleaks" in sys.argv[1:]:
        # Check if the user provided the "gitleaks" command
        sys.argv.remove("gitleaks")

    return report_file


# Main function to run the pipeline
def main():
    # Create the report file with timestamp using Pydantic
    report_file = ReportFile.create_with_timestamp().generate_filename()
    
    # Check the user-provided arguments
    report_file = check_args(report_file)

    # Build the Gitleaks command
    command_args = ["gitleaks"] + sys.argv[1:]

    # Run Gitleaks and transform the results to the desired format
    run_gitleaks(command_args, report_file)
    transform_results(report_file)


if __name__ == "__main__":
    main()
