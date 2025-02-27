import streamlit as st
import os
from zapv2 import ZAPv2 as zape
import time
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Streamlit UI setup
st.title("Piaegis Sword ⚔️")

# Input for target URL
target_url = st.text_input("Enter Target URL to Scan:", "http://example.com")
scan_button = st.button("Start Scan")

zap_results_area = st.empty()

# Function to get API keys
def get_api_key(key_name, secret_key_name):
    api_key = os.environ.get(key_name)
    if not api_key:
        try:
            api_key = st.secrets[secret_key_name]
        except KeyError:
            st.error(f"Please set the {key_name} environment variable or add it to Streamlit secrets as {secret_key_name}.")
            st.stop()
    return api_key

# ZAP configuration
zap_api_key = get_api_key('ZAP_API_KEY', 'ZAP_API_KEY')
zap_address = 'localhost'
zap_port = 8080
zap = zape(apikey=zap_api_key, proxies={'http': f'http://{zap_address}:{zap_port}', 'https': f'http://{zap_address}:{zap_port}'})

# Gemini configuration
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

# Model setup
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
    model_name="gemini-2.0-flash",
    generation_config=generation_config,
)

chat_session = model.start_chat(history=[])

# ZAP scan function
def run_zap_scan(url):
    zap_results_area.info(f"Starting ZAP Scan against: {url}")
    try:
        zap.spider.scan(url=url)
        while int(zap.spider.status()) < 100:
            time.sleep(5)
            zap_results_area.info(f"Spider progress: {zap.spider.status()}%")

        zap.ascan.scan(url=url)
        while int(zap.ascan.status()) < 100:
            time.sleep(5)
            zap_results_area.info(f"Active Scan progress: {zap.ascan.status()}%")

        xml_report = zap.core.xmlreport()
        return xml_report
    except Exception as e:
        zap_results_area.error(f"Error during ZAP Scan: {e}")
        st.exception(e)
        return None

# Gemini report generation function
def generate_gemini_report(xml_report):
    prompt = f"""Generate a **detailed and comprehensive security vulnerability report** based on the following OWASP ZAP XML report. The output **MUST** be in Markdown format

    Your report should follow this structure:

    ## Security Vulnerability Report


    **Vulnerability Details and Remediation Steps:**

    **[Vulnerability Name]**

    *   **Vulnerability Name:** [Vulnerability Name]
    *   **Severity:** [Severity Level]
    *   **Affected URL:** [Affected URL]
    *   **Description:** [Detailed description of the vulnerability] (dont include XML content directly)
    *   **Remediation Steps:**
        *   [Actionable remediation steps]
        *   ...

    ** [Next Vulnerability Name]**

    ...

    Follow this structure strictly.

    Report Details:
    1. **Identify and list all security vulnerabilities** discovered in the XML report.
    2. For each vulnerability, provide a **detailed description** including:
        * Vulnerability name
        * Severity level (High, Medium, Low, Informational)
        * Affected URL(s) or components
        * Detailed description of the vulnerability
        * **Specific evidence or excerpts from the XML report** to support your findings (if possible and relevant), pasted as XML within a code block.
    3. For each vulnerability, suggest **clear and actionable remediation steps** that developers can take to fix the issue.
    4. Provide an **executive summary** at the beginning of the report, highlighting the most critical vulnerabilities and overall security posture based on the scan.
    5. Organize the report in a **structured and easy-to-read format**, using headings, bullet points, and clear language.

    ZAP XML Report:
    ```xml
    {xml_report}
    ```
    """
    response = chat_session.send_message(prompt)
    return response.text

# Main logic
if scan_button:
    if not target_url:
        st.warning("Please enter a target URL.")
    else:
        xml_report = run_zap_scan(target_url)
        if xml_report:
            #st.subheader("ZAP XML Report:")
            #st.code(xml_report, language='xml') # Removed raw XML printing
            report = generate_gemini_report(xml_report)
            # Extract the markdown from the Gemini response
            try:
                st.write(report)
            except IndexError:
                st.error("Could not extract Markdown from Gemini's response. Displaying raw response instead.")
                st.write(report) #Fallback to raw response in case of parsing issues
        else:
            zap_results_area.warning("ZAP scan failed. Check the logs for details.")
