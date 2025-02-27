# Piaegis: Advanced SAST & DAST Powered by LLM Agents ⚔️🛡️

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Piaegis** is an innovative security tool suite that leverages the power of Large Language Models (LLMs) to enhance Static and Dynamic Application Security Testing (SAST & DAST). It aims to provide developers and security professionals with intelligent vulnerability analysis, insightful reporting, and actionable remediation guidance, all within a streamlined and user-friendly interface.

## Features

Piaegis offers a range of security analysis capabilities, including:

*   **Static Application Security Testing (SAST):**
    *   Powered by LLM Agents for intelligent code analysis.
    *   Detects a wide range of vulnerabilities across different programming languages and project types.
    *   Specialized agents for identifying:
        *   Injection Flaws (SQL, Command, Code Injection)
        *   Insecure Design
        *   Cryptographic Failures
        *   Memory Management Issues (C/C++)
        *   Path Traversal
        *   Hardcoded Secrets
        *   Insecure Defaults
        *   Serialization Issues
    *   Provides detailed vulnerability reports with severity levels, descriptions, and remediation steps.
*   **Dynamic Application Security Testing (DAST):**
    *   Integration with OWASP ZAP for comprehensive web application scanning.
    *   Automated spidering and active scanning of target URLs.
    *   LLM-powered report generation from ZAP XML reports, providing clear and actionable security insights.
*   **Interactive Security Debugging:**
    *   **Piaegis Fortify:** An AI-powered security debugger for interactive vulnerability analysis and remediation guidance.
    *   Conversational interface to discuss codebase security with an LLM agent.
    *   Context-aware responses based on the entire codebase and commit history.
    *   Helps developers understand vulnerabilities and provides code-based remediation advice.
*   **DevSecOps Pipeline Integration:**
    *   Designed for integration into CI/CD pipelines.
    *   Provides security gate functionality to ensure code deployments meet security standards.
    *   Visual representation of the DevSecOps pipeline stages.
*   **User-Friendly Interface:**
    *   Built with Streamlit for easy accessibility and intuitive usage.
    *   Web-based interface for both SAST and DAST functionalities.
    *   Clear and structured vulnerability reports.

## Getting Started

Follow these steps to get Piaegis up and running on your local machine.

### Prerequisites

Before you begin, ensure you have the following installed:

1.  **Docker**: Piaegis utilizes Docker and Docker Compose for easy setup and dependency management. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) for your operating system.
2.  **OWASP ZAP**: Piaegis Sword (DAST component) relies on OWASP ZAP. Download and install [OWASP ZAP](https://www.zaproxy.org/). Ensure ZAP is running and accessible, typically on `localhost:8080`.

### Installation and Setup

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/akash-mondal/Piaegis.git
    cd Piaegis
    ```

2.  **Create `.env` File:**

    Copy the `.env.template` file to `.env` and fill in the required environment variables.

    ```bash
    cp .env.template .env
    ```

    Edit the `.env` file with your preferred text editor and provide the necessary API keys and configurations.

    ```env
    isDevelopmentMode=enabled
    ENV=development
    OPENAI_API_KEY=<your-openai-key>         # API key for OpenAI (if using)
    GEMINI_API_KEY=<gemini-api-key>           # API key for Google Gemini
    ZAP_API_KEY=<zap client api>              # API key for OWASP ZAP API
    POSTGRES_SERVER=postgresql://postgres:mysecretpassword@localhost:5432/momentum # PostgreSQL database connection string
    NEO4J_URI=bolt://127.0.0.1:7687         # Neo4j database URI
    NEO4J_USERNAME=neo4j                     # Neo4j username
    NEO4J_PASSWORD=mysecretpassword             # Neo4j password
    REDISHOST=127.0.0.1                       # Redis host
    REDISPORT=6379                        # Redis port
    BROKER_URL=redis://127.0.0.1:6379/0        # Celery broker URL
    CELERY_QUEUE_NAME=dev                   # Celery queue name
    defaultUsername=defaultuser               # Default username for the application
    PROJECT_PATH=projects                     # Path to store downloaded/cloned repositories
    LLM_PROVIDER=openrouter                   # LLM provider (e.g., openrouter, openai, gemini)
    LLM_API_KEY=sk-or-your-key                # API key for the LLM provider
    LOW_REASONING_MODEL=openrouter/deepseek/deepseek-chat # LLM model for low reasoning tasks
    HIGH_REASONING_MODEL=openrouter/deepseek/deepseek-chat # LLM model for high reasoning tasks
    ```

    **Note:**
    *   Ensure you have API keys for your chosen LLM provider (OpenAI, Gemini, etc.) and OWASP ZAP if you intend to use DAST features.
    *   If you are working outside of development mode, make sure to place your `service-account.json` file in the root directory for Google Cloud service account authentication if needed.

3.  **Run `start.sh` Script:**

    Execute the `start.sh` script from the repository's root directory. This script will:

    *   Start Docker Compose containers (PostgreSQL, Redis, Neo4j, ZAP).
    *   Install Python dependencies from `requirements.txt`.
    *   Apply database migrations.
    *   Start the Piaegis application components: `piaegis-sheild.py`, `piaegis-sword.py`, and `Fortify.py`.

    ```bash
    chmod +x start.sh  # Make the script executable (if needed)
    ./start.sh
    ```

4.  **Access Piaegis:**

    Once the `start.sh` script completes successfully, Piaegis will be running and accessible in your web browser at the following URLs:

    *   **Piaegis Shield (SAST Agents):**  `http://localhost:8501`
    *   **Piaegis Sword (DAST Scanner):** `http://localhost:8502`
    *   **Piaegis Fortify (Interactive Debugger):** `http://localhost:8503`

## Usage

Piaegis is composed of three main tools, each accessible through a separate Streamlit application:

*   **Piaegis Shield 🛡️:** This is the main SAST interface. Navigate to `http://localhost:8501` to:
    *   Configure your repository path and file types for analysis.
    *   Run individual security agents (e.g., Injection Agent, Cryptographic Failures Agent) to scan your codebase for specific vulnerability types.
    *   View detailed analysis reports with vulnerability metrics and findings.
*   **Piaegis Sword ⚔️:**  This tool provides DAST capabilities. Access it at `http://localhost:8502` to:
    *   Enter a target URL to scan.
    *   Initiate OWASP ZAP scans (spider and active scan).
    *   Generate LLM-powered security vulnerability reports from ZAP XML output in Markdown format.
*   **Piaegis Fortify 🛡️:**  The interactive security debugger is available at `http://localhost:8503`.
    *   Configure your repository path and file types.
    *   Engage in a conversational chat with the AI agent about your codebase security.
    *   Ask questions about potential vulnerabilities, remediation advice, and security best practices.

## Architecture and Components

Piaegis is built with a modular architecture, comprising the following key components:

*   **Streamlit Applications:**
    *   `piaegis-sheild.py`:  Provides the user interface for SAST agents and analysis reports.
    *   `piaegis-sword.py`:  Offers DAST scanning functionality using OWASP ZAP and LLM reporting.
    *   `Fortify.py`:  Implements the interactive security debugging agent.
*   **LLM Agents:**  Python classes (`InjectionAgent`, `InsecureDesignAgent`, etc.) that define specific security analysis logic and interact with the LLM API.
*   **Core Functions:**  Utility functions for code scraping, file handling, Git operations, and LLM interaction (defined in `piaegis-sheild.py` and `piaegis-sword.py`).
*   **Docker Compose:**  Manages the necessary services like PostgreSQL, Redis, Neo4j, and OWASP ZAP for the application to run.
*   **Celery:**  Used for asynchronous task processing (details in `app/celery.py` if applicable).
*   **Databases:**
    *   PostgreSQL: For application data storage (if used).
    *   Neo4j:  For graph-based security analysis (if used).
    *   Redis:  For Celery broker and caching.

## License

Piaegis is released under the [Apache 2.0 License](LICENSE).

## Contributing

We welcome contributions to Piaegis!  If you'd like to contribute, please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and ensure they are well-tested.
4.  Submit a pull request with a clear description of your changes.

## Support and Contact

For questions, issues, or feedback, please open an issue on the [GitHub repository](https://github.com/akash-mondal/Piaegis/issues).

---

Thank you for using Piaegis! We hope it helps you build more secure applications.
