import os
import subprocess
import chardet
import streamlit as st
import google.generativeai as genai
from google.ai.generativelanguage_v1beta.types import content
import json
from dotenv import load_dotenv
from abc import ABC, abstractmethod
import plotly.graph_objects as go
import streamlit_mermaid as stmd

load_dotenv()

# --- Configuration and Core Functions (Keep these as before) ---
PRESET_FILE_TYPES = {
    ".NET Projects": (".cs", ".csproj", ".sln", ".config", ".aspx", ".cshtml"),
    "JavaScript Web Apps": (".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".json"),
    "Java (Eclipse) Projects": (".java", ".jsp", ".xml", ".gradle", ".properties", ".project", ".classpath"),
    "Python Projects": (".py", ".pyw", ".ini", ".cfg", ".txt", ".yaml", ".yml", ".json"),
    "Android Studio Projects": (".java", ".kt", ".xml", ".gradle", ".properties", ".manifest"),
    "All Supported Types": ('.py', '.java', '.c', '.cpp', '.h', '.hpp', '.js', '.html', '.css', '.xml', '.json', '.txt', '.md',
              '.sh', '.gradle', '.kt', '.swift', '.cs', '.vb', '.php', '.rb', '.go', '.sql', '.ini', '.config',
              '.properties', '.yaml', '.yml', '.gitignore', '.dockerfile', '.tf', '.tfvars', '.pom', '.jsp', '.aspx',
              '.asp', '.xhtml')
}
DEFAULT_PRESET = "All Supported Types"

def get_file_encoding(file_path): # ... (rest of core functions: get_file_encoding, read_file_content, get_current_commit_changes, scrape_code, create_codebase_string, generate_analysis, format_vulnerability)
    try:
        with open(file_path, 'rb') as f:
            result = chardet.detect(f.read())
            return result['encoding']
    except:
        return 'utf-8'

def read_file_content(file_path):
    encoding = get_file_encoding(file_path)
    try:
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return ""

def get_current_commit_changes(repo_path):
    try:
        result = subprocess.run(['git', 'diff', 'HEAD'], cwd=repo_path, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error getting commit changes: {e}")
        return "Error retrieving commit information."

def scrape_code(repo_path, file_types):
    codebase = {}
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(file_types):
                file_path = os.path.join(root, file)
                codebase[file_path] = read_file_content(file_path)
    return codebase

def create_codebase_string(codebase, commit_changes):
    codebase_string = "```\n"
    for file_path, content in codebase.items():
        codebase_string += f"\n--- File: {file_path} ---\n"
        codebase_string += content + "\n"
    codebase_string += f"\n--- Last Commit Changes ---\n{commit_changes}\n```"
    return codebase_string

def generate_analysis(codebase_string, system_instruction, response_schema):
    genai.configure(api_key=os.environ["GEMINI_API_KEY"])

    generation_config = {
        "temperature": 0.2,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
        "response_schema": response_schema,
        "response_mime_type": "application/json",
    }

    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        generation_config=generation_config,
        system_instruction=system_instruction,
    )

    try:
        response = model.generate_content(codebase_string)
        json_string = response.text.strip().replace("```json\n", "").replace("\n```", "")
        return json.loads(json_string)
    except Exception as e:
        print(f"Error during LLM call: {e}")
        st.error(f"Error during LLM call: {e}")
        return None

def format_vulnerability(vulnerability):
    return f"- **File:** {vulnerability['path']}\n  - **Severity:** {vulnerability['severity']}\n  - **Description:** {vulnerability['description']}"


# --- Agent Definitions (Keep these as before, only update mermaid_diagram_code) ---
class BaseAgent(ABC): # ... (rest of BaseAgent class - no changes needed)
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def target(self) -> str:
        pass

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def mermaid_diagram_code(self) -> str: # New property for Mermaid diagram
        pass


    @property
    def response_schema(self):
      return content.Schema(
        type = content.Type.OBJECT,
        properties = {
          "critical_issues_number": content.Schema(
            type = content.Type.NUMBER,
          ),
          "medium_issues_number": content.Schema(
            type = content.Type.NUMBER,
          ),
          "low_issues_number": content.Schema(
            type = content.Type.NUMBER,
          ),
          "vulnerabilities": content.Schema(
            type = content.Type.ARRAY,
            items = content.Schema(
              type = content.Type.OBJECT,
              enum = [],
              required = ["description", "path", "severity"],
              properties = {
                "description": content.Schema(
                  type = content.Type.STRING,
                ),
                "path": content.Schema(
                  type = content.Type.STRING,
                ),
                "severity": content.Schema(
                  type = content.Type.STRING,
                ),
              },
            ),
          ),
        },
      )

    def analyze(self, codebase_string):
        return generate_analysis(codebase_string, self.system_prompt, self.response_schema)


class InjectionAgent(BaseAgent): # ... (rest of Agent classes - no changes needed except mermaid_diagram_code)
    @property
    def name(self) -> str:
        return "Injection Flaws"

    @property
    def target(self) -> str:
        return "SQL Injection, Command Injection, Code Injection"

    @property
    def system_prompt(self) -> str:
        return """You are a security analyst specializing in identifying injection flaws. Analyze the provided codebase and provide JSON output."""

    @property
    def description(self) -> str:
        return "Detects vulnerabilities related to injection flaws, such as SQL, Command, and Code Injection. Focuses on identifying areas where user input is improperly handled in queries and commands."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Injection Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class InsecureDesignAgent(BaseAgent):
    @property
    def name(self):
        return 'Insecure Design'

    @property
    def target(self) -> str:
        return "Insecure Design (A04)"

    @property
    def system_prompt(self):
        return """You are a security analyst specializing in identifying insecure design and logic flaws.  Provide JSON output."""

    @property
    def description(self) -> str:
        return "Analyzes the codebase for insecure design and logic flaws. This agent identifies weaknesses in architecture, authentication, authorization, and session management."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Insecure Design Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class CryptographicFailuresAgent(BaseAgent):
    @property
    def name(self):
        return "Cryptographic Failures"

    @property
    def target(self) -> str:
        return "Cryptographic Failures (A02), CWE-347, CWE-522"

    @property
    def system_prompt(self):
        return """You are a security analyst specializing in cryptographic failures. Provide JSON output."""

    @property
    def description(self) -> str:
        return "Identifies cryptographic failures, including weak algorithms, improper key management, and incorrect use of crypto libraries. It also checks for insufficiently protected credentials."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Crypto Failures Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class MemoryManagementAgent(BaseAgent):
    @property
    def name(self):
        return "Memory Management"

    @property
    def target(self) -> str:
        return "CWE-787, CWE-416"

    @property
    def system_prompt(self):
        return """You are a security analyst specializing in memory management issues in C and C++ code. Provide JSON output."""

    @property
    def description(self) -> str:
        return "Specializes in memory management vulnerabilities such as buffer overflows, use-after-free errors, and memory leaks, specifically in C and C++ codebases."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage (C/C++)};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Memory Mgmt Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O[Production Deployment];
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class PathTraversalAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "Path Traversal"

    @property
    def target(self) -> str:
        return "Security Misconfiguration (A05), CWE-22"

    @property
    def system_prompt(self) -> str:
      return  """You are a security analyst specializing in path traversal vulnerabilities. Provide JSON output."""

    @property
    def description(self) -> str:
        return "Detects path traversal vulnerabilities, focusing on insecure file handling and manipulation of file paths based on user-controlled input."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Path Traversal Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class HardcodedSecretsAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "Hardcoded Secrets"

    @property
    def target(self) -> str:
      return "Cryptographic Failures (A02), CWE-522"

    @property
    def system_prompt(self) -> str:
      return """You are a security analyst focused on identifying hardcoded secrets and insecure credential storage. Provide JSON output."""

    @property
    def description(self) -> str:
        return "Focuses on finding hardcoded secrets like passwords and API keys, as well as insecure storage of credentials within the codebase."

    @property
    def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Hardcoded Secrets Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""

class InsecureDefaultsAgent(BaseAgent):
  @property
  def name(self):
      return "Insecure Defaults"

  @property
  def target(self) -> str:
      return "Security Misconfiguration (A05), CWE-276"

  @property
  def system_prompt(self):
      return """You are a security analyst specializing in identifying insecure default configurations. Provide JSON output."""

  @property
  def description(self) -> str:
      return "Identifies insecure default configurations that could lead to vulnerabilities, such as default passwords, unnecessary enabled services, and permissive permissions."

  @property
  def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Insecure Defaults Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O[Production Deployment];
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""


class SerializationIssuesAgent(BaseAgent):
  @property
  def name(self):
      return "Serialization Issues"

  @property
  def target(self) -> str:
      return "Insecure Deserialization (A04), CWE-502"

  @property
  def system_prompt(self):
      return """You are a security analyst specializing in insecure deserialization vulnerabilities. Provide JSON output."""

  @property
  def description(self) -> str:
      return "Analyzes for insecure deserialization vulnerabilities, checking for unsafe use of serialization libraries and potential remote code execution risks."

  @property
  def mermaid_diagram_code(self) -> str:
        return """
graph LR
    A[Code Commit] --> B{Build Stage};
    B --> C[Unit Tests];
    C --> D{SAST Stage};
    D --> D1[Serialization Agent];
    style D1 fill:#ccf,stroke:#333,stroke-width:2px
    D --> D2[Other SAST Tools];
    D --> E{DAST Stage};
    E --> F[Security Tests];
    F --> G[IaC Scan];
    G --> H[Dependency Scan];
    H --> I[Container Scan];
    I --> J{Security Gate};
    J -- Approved --> K[Deploy to Staging];
    J -- Rejected --> L[Fail Pipeline & Notify Dev];
    K --> M[Integration Tests];
    M --> N{Pre-Prod Security Scan};
    N --> O{Production Deployment};
    O --> P[Runtime Monitoring];
    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""


AGENTS = [ # ... (rest of AGENTS list - no changes needed)
    InjectionAgent(),
    InsecureDesignAgent(),
    CryptographicFailuresAgent(),
    MemoryManagementAgent(),
    PathTraversalAgent(),
    HardcodedSecretsAgent(),
    InsecureDefaultsAgent(),
    SerializationIssuesAgent(),
]

# --- Streamlit UI and Navigation---

def show_home_page(): # ... (rest of show_home_page function - add pipeline diagram display)
    st.header("Security Agents")
    cols = st.columns(4)
    for i, agent in enumerate(AGENTS):
        with cols[i % 4]:
            with st.container():
                st.markdown(f"<div class='agent-card'><div class='agent-name'>{agent.name}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='agent-target'>{agent.target}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='agent-description'>{agent.description}</div>", unsafe_allow_html=True)
                # Display running status
                if st.session_state.get(f'running_{agent.name}'):
                    st.info(f"Running {agent.name}...")
                else:
                    if st.button(f"Run {agent.name}", key=f"run_agent_{agent.name}"):
                        st.session_state[f'running_{agent.name}'] = True  # Set running status
                        st.session_state.selected_agent = agent.name
                        st.session_state.page = "analysis"
                        st.rerun() # Force re-run to update UI immediately

    st.markdown("---")
    st.subheader("DevSecOps Pipeline Integration")
    pipeline_diagram_code = """
graph LR
    subgraph Code Development
    A[Code Commit] --> B{Build Stage}
    end

    subgraph Testing & Security
    B --> C[Unit Tests]
    C --> D{SAST Stage}
    D --> D1[Injection Agent]
    D --> D2[Insecure Design Agent]
    D --> D3[Crypto Failures Agent]
    D --> D4[Memory Mgmt Agent]
    D --> D5[Path Traversal Agent]
    D --> D6[Hardcoded Secrets Agent]
    D --> D7[Insecure Defaults Agent]
    D --> D8[Serialization Agent]
    D --> D9[Other SAST Tools]
    D --> E{DAST Stage}
    E --> F[Security Tests]
    F --> G[IaC Scan]
    G --> H[Dependency Scan]
    H --> I[Container Scan]
    end

    I --> J{Security Gate}
    J -- Approved --> K[Deploy to Staging]
    J -- Rejected --> L[Fail Pipeline & Notify Dev]

    subgraph Deployment & Monitoring
    K --> M[Integration Tests]
    M --> N{Pre-Prod Security Scan}
    N --> O[Production Deployment]
    O --> P[Runtime Monitoring]
    end

    style D fill:#f9f,stroke:#333,stroke-width:2px
    style J fill:#afa,stroke:#333,stroke-width:2px
    style D1 fill:#ccf,stroke:#333,stroke-width:1px
    style D2 fill:#ccf,stroke:#333,stroke-width:1px
    style D3 fill:#ccf,stroke:#333,stroke-width:1px
    style D4 fill:#ccf,stroke:#333,stroke-width:1px
    style D5 fill:#ccf,stroke:#333,stroke-width:1px
    style D6 fill:#ccf,stroke:#333,stroke-width:1px
    style D7 fill:#ccf,stroke:#333,stroke-width:1px
    style D8 fill:#ccf,stroke:#333,stroke-width:1px
    style D9 fill:#ccf,stroke:#333,stroke-width:1px

    classDef pipelineNode fill:#fff,stroke:#333,stroke-width:2px
    class A,B,C,D,E,F,G,H,I,J,K,M,N,O,P pipelineNode
"""
    stmd.st_mermaid(pipeline_diagram_code, height=700)


def show_analysis_page(selected_agent_name): # ... (rest of show_analysis_page and main functions - no changes needed)
    selected_agent = next((agent for agent in AGENTS if agent.name == selected_agent_name), None)
    if not selected_agent:
        st.error(f"Agent '{selected_agent_name}' not found.")
        return

    st.subheader(f"{selected_agent.name} - Analysis Report")
    st.markdown(f"<div class='agent-target'>Targeting: {selected_agent.target}</div>", unsafe_allow_html=True)

    # Run analysis if not already run (or if re-running)
    if st.session_state.get(f'running_{selected_agent.name}') or f'analysis_result_{selected_agent.name}' not in st.session_state :
        with st.spinner(f"Analyzing code with {selected_agent.name}..."):
            codebase = scrape_code(st.session_state.repo_path, st.session_state.file_types)
            commit_changes = get_current_commit_changes(st.session_state.repo_path)
            codebase_string = create_codebase_string(codebase, commit_changes)
            st.session_state[f'analysis_result_{selected_agent.name}'] = selected_agent.analyze(codebase_string)
        st.session_state[f'running_{selected_agent.name}'] = False  # Reset running status
        st.session_state.page = "analysis" # Stay on analysis page after run
        st.rerun() #re render


    if f'analysis_result_{selected_agent.name}' in st.session_state:
        analysis_result = st.session_state[f'analysis_result_{selected_agent.name}']

        if analysis_result:
            # Display Metrics (back to counters)
            st.markdown(f"""<div class='metrics'>
                <div class='metric-box'><div class='metric-value'>{analysis_result.get('critical_issues_number', 0)}</div>Critical Issues</div>
                <div class='metric-box'><div class='metric-value'>{analysis_result.get('medium_issues_number', 0)}</div>Medium Issues</div>
                <div class='metric-box'><div class='metric-value'>{analysis_result.get('low_issues_number', 0)}</div>Low Issues</div>
            </div>""", unsafe_allow_html=True)
            # Vulnerabilities
            if analysis_result.get('vulnerabilities'):
                st.markdown(f"##### Vulnerabilities")
                for vulnerability in analysis_result['vulnerabilities']:
                    severity_class = vulnerability['severity'].lower()
                    st.markdown(f"""
                    <div class="vulnerability-report">
                        <p><strong>File:</strong> {vulnerability['path']}</p>
                        <p><strong>Severity:</strong> <span class='severity-badge {severity_class}'>{vulnerability['severity']}</span></p>
                        <p><strong>Description:</strong> {vulnerability['description']}</p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("No vulnerabilities found.")
        else:
            st.error(f"Analysis failed. See console for error messages.")
    # Back button
    if st.button("Back to Home"):
        st.session_state.page = "home"
        st.rerun()


def main(): # ... (rest of main function - no changes needed)
    st.set_page_config(page_title="Piaegis Sheild 🛡️", page_icon=":lock:", layout="wide")

     # Custom CSS
    st.markdown(
        """
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f0f2f6;
                color: #31333F;
            }
            .sidebar .sidebar-content {
                background: linear-gradient(135deg, #4A90E2, #63b8ff);
                color: white;
            }
            .stButton>button {
                color: white;
                border-radius: 20px;
                border: 1px solid #4A90E2;
                background-color: #4A90E2;
                padding: 0.5rem 1rem;
                transition: all 0.3s ease;
                width: 100%;
            }
            .stButton>button:hover {
                background-color: #63b8ff;
                border-color: #63b8ff;
            }
            h1, h2, h3 {
                color: #4A90E2;
            }
            .agent-card {
                background-color: white;
                border-radius: 10px;
                padding: 1rem;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                margin-bottom: 1rem;
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                align-items: center; /* Center content vertically */
                text-align: center; /* Center text horizontally */
            }
            .agent-name {
                color: #4A90E2;
                font-size: 1.5rem;
                font-weight: bold;
                margin-bottom: 0.5rem;
            }
            .agent-target {
                color: #666;
                font-size: 0.9rem;
                margin-bottom: 0.7rem;
                font-style: italic;
            }
            .agent-description {
                margin-bottom: 0.5rem; /* Reduced margin */
                font-size: 1rem;
            }
             .vulnerability-report {
                border-left: 4px solid #4A90E2;
                padding-left: 10px;
                margin-top: 10px;
            }
            .severity-badge {
                display: inline-block;
                padding: 0.2rem 0.5rem;
                border-radius: 5px;
                font-size: 0.8rem;
                font-weight: bold;
            }
            .critical { background-color: #ff4b4b; color: white; }
            .medium { background-color: #ffcc00; color: black; }
            .low { background-color: #4CAF50; color: white; }
            .metrics {
                display: flex;
                gap: 20px;
                margin-bottom: 20px;
            }
            .metric-box {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 10px;
                text-align: center;
                min-width: 100px;
                background-color: #f9f9f9;
            }
            .metric-value {
                font-size: 1.5em;
                font-weight: bold;
                color: #4A90E2;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.title("Piaegis Sheild 🛡️")

    # Initialize session state
    if "page" not in st.session_state:
        st.session_state.page = "home"
    for agent in AGENTS:
        if f'running_{agent.name}' not in st.session_state:
            st.session_state[f'running_{agent.name}'] = False
    if "repo_path" not in st.session_state:
        st.session_state.repo_path = "."
    if "file_types" not in st.session_state:
        st.session_state.file_types = PRESET_FILE_TYPES[DEFAULT_PRESET]


    # Sidebar for Configuration
    with st.sidebar:
        st.header("Repository Configuration")
        repo_path = st.text_input("Enter repository path:", value=st.session_state.repo_path, key="repo_path")
        if not os.path.isdir(repo_path):
            st.error("Invalid repository path.")
            st.stop()

        preset_options = list(PRESET_FILE_TYPES.keys())
        preset_options.insert(0, "Custom File Types")
        selected_preset = st.selectbox("Select Project Type", preset_options, index=preset_options.index(st.session_state.get("selected_preset", DEFAULT_PRESET)) if DEFAULT_PRESET in preset_options else 0, key="selected_preset")

        if selected_preset == "Custom File Types":
            file_types_input = st.text_input("Custom File Types (comma-separated):", value=",".join(st.session_state.get("file_types", PRESET_FILE_TYPES[DEFAULT_PRESET])), key="file_types_input")
            file_types = tuple(ft.strip() for ft in file_types_input.split(","))
        else:
            file_types = PRESET_FILE_TYPES[selected_preset]

        st.session_state.file_types = file_types

    # Display current page
    if st.session_state.page == "home":
        show_home_page()
    elif st.session_state.page == "analysis":
        show_analysis_page(st.session_state.selected_agent)


if __name__ == "__main__":
    main()
