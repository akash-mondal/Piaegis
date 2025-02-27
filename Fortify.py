import os
import subprocess
import chardet
import streamlit as st
import google.generativeai as genai
from google.ai.generativelanguage_v1beta.types import content
from dotenv import load_dotenv

load_dotenv()

# --- Configuration and Core Functions (Minimal set needed for Fortify) ---
PRESET_FILE_TYPES = { # Keep if you want preset file types in Fortify config
    ".NET Projects": (".cs", ".csproj", ".sln", ".config", ".aspx", ".cshtml"),
    "JavaScript Web Apps": (".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".json"),
    "Java (Eclipse) Projects": (".java", ".jsp", ".xml", ".gradle", ".properties", ".project", ".classpath"),
    "Python Projects": (".py", ".pyw", ".ini", ".cfg", ".txt", ".yaml", ".yml", ".json"),
    "Android Studio Projects": (".java", ".kt"),
    "All Supported Types": ('.py', '.java', '.c', '.cpp', '.h', '.hpp', '.js', '.html', '.css', '.xml', '.json', '.txt', '.md',
              '.sh', '.gradle', '.kt', '.swift', '.cs', '.vb', '.php', '.rb', '.go', '.sql', '.ini', '.config',
              '.properties', '.yaml', '.yml', '.gitignore', '.dockerfile', '.tf', '.tfvars', '.pom', '.jsp', '.aspx',
              '.asp', '.xhtml')
}
DEFAULT_PRESET = "All Supported Types"

def get_file_encoding(file_path):
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


# --- Fortify Agent Class (Standalone) ---
class FortifyAgent: # Not inheriting from BaseAgent as it's a different typ	e of agent - conversational
    @property
    def name(self) -> str:
        return "Piaegis Fortify"

    @property
    def description(self) -> str:
        return "AI-powered security debugger for interactive vulnerability analysis and remediation guidance."

    def generate_response(self, codebase_string, user_input, chat_history):
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        model = genai.GenerativeModel(model_name="gemini-2.0-flash")

        system_instruction = """You are Piaegis Fortify, an AI-powered security debugger.
You are helping a developer analyze a codebase for security vulnerabilities and provide remediation advice.
You have access to the entire codebase. Use this codebase to provide context-aware and accurate answers.
Engage in a helpful and informative conversation. When providing code examples, use markdown formatting.
Focus on security best practices and remediation steps.

YOU WILL BE GIVEN VULNERABILITIES THEIR PATH AND PROBLEMS DETECTED AND YOU HAVE TO GIVE THE BEST CODE BASED REMIDATION

this is my raw codebase i have put in with paths to help you with understand it , use this to understand the structure of the whole project
**Codebase:**
{codebase}

when answering questions be concise and helpful for fast debugging , help the User Understand which File has to be edited and what has to be changed 
give full codes always
"""

        prompt_parts = [
            content.Content(
                role="user",
                parts=[content.Part(text=system_instruction.format(codebase=codebase_string))],
            )
        ]
        # Add chat history to the prompt
        for msg in chat_history:
            prompt_parts.append(content.Content(role=msg["role"], parts=[content.Part(text=msg["content"])]))

        # Add current user input
        prompt_parts.append(content.Content(role="user", parts=[content.Part(text=user_input)]))


        generation_config = {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 8192,
        }

        try:
            response = model.generate_content(
                contents=prompt_parts,
                generation_config=generation_config,
            )
            return response.text
        except Exception as e:
            print(f"Error during Fortify Agent LLM call: {e}")
            st.error(f"Error during Fortify Agent LLM call: {e}")
            return "Error generating response."


FORTIFY_AGENT = FortifyAgent()


# --- Streamlit UI for Fortify (Standalone App) ---
def show_fortify_page():
    st.markdown(f"<div class='agent-description'>{FORTIFY_AGENT.description}</div>", unsafe_allow_html=True)

    if 'fortify_chat_history' not in st.session_state:
        st.session_state['fortify_chat_history'] = []
    if 'fortify_codebase_string' not in st.session_state:
        codebase = scrape_code(st.session_state.repo_path, st.session_state.file_types)
        commit_changes = get_current_commit_changes(st.session_state.repo_path)
        st.session_state['fortify_codebase_string'] = create_codebase_string(codebase, commit_changes)


    codebase_string = st.session_state['fortify_codebase_string']

    # Chat Interface
    chat_placeholder = st.empty() # Placeholder for chat messages
    with chat_placeholder.container():
        for msg in st.session_state['fortify_chat_history']:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    prompt = st.chat_input("Ask Piaegis Fortify about your code...")
    if prompt:
        st.session_state['fortify_chat_history'].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                response = FORTIFY_AGENT.generate_response(codebase_string, prompt, st.session_state['fortify_chat_history'])
                st.session_state['fortify_chat_history'].append({"role": "assistant", "content": response})
                st.markdown(response)
        # Rerender chat messages to show new messages - REMOVED THIS LINE
        # chat_placeholder.rerender()

def main():
    st.set_page_config(page_title="Piaegis Fortify 🛡️", page_icon=":wrench:", layout="wide") # Different title and icon

     # Custom CSS (Keep styling, adjust if needed)
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
            .agent-description {
                margin-bottom: 0.5rem; /* Reduced margin */
                font-size: 1rem;
            }

            /* Code Display Styling */
            .code-display-container {
                background-color: #f0f2f6; /* Match background */
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 1rem;
                margin-bottom: 1rem;
                overflow-x: auto; /* Horizontal scroll if needed */
                max-height: 400px; /* Adjust as needed */
            }
            .code-display-container pre {
                margin: 0; /* Remove default pre margins */
                padding: 0;
                background-color: transparent; /* Ensure pre is transparent */
            }


        </style>
        """,
        unsafe_allow_html=True,
    )
    st.title("Piaegis Fortify 🛡️") # Different Title

    # Initialize session state
    if "repo_path" not in st.session_state:
        st.session_state.repo_path = "."
    if "file_types" not in st.session_state:
        st.session_state.file_types = PRESET_FILE_TYPES[DEFAULT_PRESET]


    # Sidebar for Configuration (Minimal Sidebar for Fortify only)
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

    # Directly show Fortify Page
    show_fortify_page()


if __name__ == "__main__":
    main()
