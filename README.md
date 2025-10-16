# dispensation-automation

## Overview

**dispensation-automation** is a Python-based automation tool designed to manage package dispensations for Checkmarx SCA (Software Composition Analysis) and CSEC (Container Security) projects. It automates the process of snoozing or ignoring vulnerabilities for specific packages in your projects, integrates with Checkmarx APIs, and provides robust logging and error handling.

The main entry point is `dispensation.py`, which orchestrates the workflow for both SCA and CSEC dispensations, including:
- Fetching project and package details from Checkmarx
- Updating package states (e.g., snooze, ignore)
- Handling errors and logging results
- Supporting both SCA and CSEC flows with configurable parameters

---

## Configuration

### Local Development

When running the script locally, you must set up environment variables using `.env` files for both Checkmarx and Jira integrations. Sample files are provided:

- `checkmarx_utility/.env_sample`
- `jira_utility/.env_sample`

**Steps:**
1. Copy the sample files to `.env` in their respective directories:
   ```sh
   cp checkmarx_utility/.env_sample checkmarx_utility/.env
   cp jira_utility/.env_sample jira_utility/.env
   ```
2. Edit the `.env` files and fill in the required values (see "JIRA Environment Variables" below).

### Production (GitHub Actions)

For production or CI/CD (e.g., GitHub Actions), **do not use .env files**.  
Instead, set the required environment variables as GitHub repository or Actions secrets.  
The script will automatically use these environment variables at runtime.

---

## JIRA Environment Variables

The following environment variables are required for Jira integration (set in `.env` for local, or as GitHub secrets for production):

- `JIRA_URL` — Base URL of your Jira instance (e.g., `https://yourcompany.atlassian.net`)
- `JIRA_USER` — Jira username or email (for API authentication)
- `JIRA_API_TOKEN` — Jira API token (generate from your Jira account)
- `JIRA_PROJECT_KEY` — Key of the Jira project where issues will be created/updated
- `JIRA_ISSUE_TYPE` — Issue type to use (e.g., `Task`, `Bug`, `Story`)
- `JIRA_FIELD_MAPPINGS` — (Optional) JSON or string mapping of script fields to Jira custom fields

**Example `.env` for Jira:**
```
JIRA_URL=https://yourcompany.atlassian.net
JIRA_USER=your.email@company.com
JIRA_API_TOKEN=your_api_token
JIRA_PROJECT_KEY=SECURITY
JIRA_ISSUE_TYPE=Task
JIRA_FIELD_MAPPINGS={"customfield_12345": "dispensation_reason", "customfield_67890": "package_list"}
```

---

## Field Mappings

Field mappings define how data from the automation script is mapped to Jira issue fields.  
This is especially important for custom fields in your Jira project.

- **Standard fields:**  
  - `summary` — Issue summary/title (e.g., "Dispensation for package X")
  - `description` — Detailed description of the dispensation request

- **Custom fields:**  
  Use the `JIRA_FIELD_MAPPINGS` variable to map script data to Jira custom fields.  
  Example:
  ```json
  {
    "customfield_12345": "dispensation_reason",
    "customfield_67890": "package_list"
  }
  ```
  - `customfield_12345` will be filled with the value of `dispensation_reason` from the script.
  - `customfield_67890` will be filled with the value of `package_list` from the script.

---

## How to Run the Script Locally

1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd dispensation-automation
   ```

2. **Set up environment variables** as described above.

3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

4. **Run the main script:**
   ```sh
   python dispensation.py
   ```

   - The script will execute the main automation flow as defined in `dispensation.py`.
   - Logs will be written to the `logs/` directory by default, unless configured otherwise.

---

## File Structure

```
dispensation-automation/
├── dispensation.py
├── requirements.txt
├── README.md
├── .gitignore
├── logs/
├── checkmarx_utility/
│   ├── __init__.py
│   ├── .env_sample
│   ├── cx_api_actions.py
│   ├── cx_api_endpoints.py
│   ├── cx_config_utility.py
│   ├── cx_helper_functions.py
│   ├── cx_token_manager.py
├── jira_utility/
│   ├── __init__.py
│   ├── .env_sample
│   ├── jira_api_actions.py
│   ├── jira_api_endpoints.py
│   ├── jira_config_utility.py
│   ├── jira_helper_functions.py
├── utils/
│   ├── exception_handler.py
│   ├── helper_functions.py
│   ├── http_utility.py
│   ├── json_file_utility.py
│   ├── logger.py
│   ├── yml_file_utility.py
```

## File/Folder Descriptions

- **dispensation.py**  
  Main entry point. Orchestrates the automation for SCA and CSEC dispensations, handles configuration, logging, and error handling.

- **requirements.txt**  
  Lists Python dependencies required for the project.

- **logs/**  
  Directory where log files are stored. Created automatically if logging to file is enabled.

- **checkmarx_utility/**  
  Contains all Checkmarx-related utilities and API integrations:
  - `cx_api_actions.py`: Main API action methods for Checkmarx (fetch projects, update package state, etc.)
  - `cx_api_endpoints.py`: API endpoint definitions for Checkmarx.
  - `cx_config_utility.py`: Loads and manages Checkmarx configuration.
  - `cx_helper_functions.py`: Helper functions for Checkmarx-specific logic.
  - `cx_token_manager.py`: Handles Checkmarx API token management.
  - `.env_sample`: Sample environment file for Checkmarx credentials/config.

- **jira_utility/**  
  Contains all Jira-related utilities and API integrations:
  - `jira_api_actions.py`: Main API action methods for Jira.
  - `jira_api_endpoints.py`: API endpoint definitions for Jira.
  - `jira_config_utility.py`: Loads and manages Jira configuration.
  - `jira_helper_functions.py`: Helper functions for Jira-specific logic.
  - `.env_sample`: Sample environment file for Jira credentials/config.

- **utils/**  
  General-purpose utilities used throughout the project:
  - `exception_handler.py`: Custom exception handling decorator for robust error management.
  - `helper_functions.py`: Miscellaneous helper functions.
  - `http_utility.py`: HTTP request abstraction layer.
  - `json_file_utility.py`: Utilities for working with JSON files.
  - `logger.py`: Flexible logger supporting file and console output.
  - `yml_file_utility.py`: Utilities for working with YAML files.

- **README.md**  
  This documentation file.

- **.gitignore**  
  Specifies files and directories to be ignored by git.

---

## Additional Notes

- **Logging:**  
  By default, logs are written to both the console and a timestamped file in the `logs/` directory. You can configure the logger to disable file logging if desired.

- **Error Handling:**  
  The project uses a custom exception handler decorator for consistent error logging and propagation.

- **Extensibility:**  
  The modular structure allows for easy extension to support additional automation tasks or integrations.

---

For further details on error handling and logging best practices, see `EXCEPTION_HANDLER_BEST_PRACTICES.md`.
