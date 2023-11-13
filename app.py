import streamlit as st
import json
import pandas as pd
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.callbacks import get_openai_callback

# Load environment variables
from dotenv import load_dotenv
import os
load_dotenv()

# Function to prepare data for analysis and table display

def extract_data(data, selected_severities):
    # Convert the 'vulnerabilities' section to a DataFrame
    vulnerabilities_df = pd.DataFrame(data['vulnerabilities'])

    # Filter for selected severities
    vulnerabilities_df = vulnerabilities_df[vulnerabilities_df['severity'].isin(selected_severities)]

    # Extract necessary fields and check for solutions
    vulnerabilities_df['has_solution'] = vulnerabilities_df['solution'].apply(lambda x: x != 'No solution provided')

    # Count total vulnerabilities by severity
    severity_counts = vulnerabilities_df['severity'].value_counts().to_dict()

    # Count fixable vulnerabilities by severity
    fixable_counts = vulnerabilities_df[vulnerabilities_df['has_solution']]['severity'].value_counts().to_dict()

    # Extract CVE and solution details for fixable vulnerabilities
    fixable_vulns = vulnerabilities_df[vulnerabilities_df['has_solution']][['severity', 'identifiers', 'solution']]

    # Constructing the result string
    result = "Vulnerability Counts by Selected Severities:\n"
    for severity, count in severity_counts.items():
        result += f" - {severity}: {count}\n"

    result += "\nFixable Vulnerability Counts by Selected Severities:\n"
    for severity, count in fixable_counts.items():
        result += f" - {severity}: {count}\n"

    # Adding fixable vulnerabilities details
    result += "\nDetails of Fixable Vulnerabilities by Selected Severities:\n"
    for _, row in fixable_vulns.iterrows():
        cve_ids = [identifier['value'] for identifier in row['identifiers'] if identifier['type'].lower() == 'cve']
        cve_ids_str = ", ".join(cve_ids) if cve_ids else "No CVE ID"
        result += f"Severity: {row['severity']}, CVE IDs: {cve_ids_str}, Solution: {row['solution']}\n"

    return result

# Function to analyze CVEs using LangChain and OpenAI
def analyze_cves_with_openai(ai_instructions, data, openai_api_key, dockerfile):
    # return cves_string
    with get_openai_callback() as cb:
        llm = ChatOpenAI(model_name=model, temperature=0.0,
                         openai_api_key=openai_api_key)
        input_variables = ["data"]
        prompt_template = PromptTemplate(
            input_variables=input_variables, template=ai_instructions)
        review_chain = LLMChain(
            llm=llm, prompt=prompt_template, output_key="feedback")
        feedback = review_chain.run({'data': data, 'dockerfile':dockerfile})
        print(cb)

    return feedback

if __name__ == '__main__':
    ai_instructions = """Act as an expert on Information Assurance and docker containers vulnerabilities.  
    Analyze the data below from a container vulnerability scan. This file contains data on various vulnerabilities found in a container. Please do the following:
Categorize all vulnerabilities by their severity (Critical, High, Medium, Low).
Provide a count for the total number of vulnerabilities in each severity category.
Identify which vulnerabilities have solutions or remediations provided.
For those with solutions, count how many there are in each severity category.
Provide details on what is needed to fix or remediate these vulnerabilities, including package upgrades or specific actions recommended.
Please format your response with clear headings for each task and present the data in an easy-to-understand manner. If a dockerfile is provided, I want you to 
analyze this dockerfile based on these CVEs and other security best practices and provide recommendations of fixes to improve the security posture of the image.  
Include details instructions an updated dockerfile that shows the changes you recommend.  You can use markup to highlight the changes to the dockerfile.

    DATA: 
    {data}    

    DOCKERFILE:
    {dockerfile}
    """

    st.set_page_config(page_title="Vulnerability Scanner Reviewer")
    st.header('🦜🔗 Vulnerability Scanner Reviewer')
    tab0, tab1, tab2 = st.tabs(
        ["Introduction", "AI Instructions", "Additional Info"])

    openai_api_key_env = os.getenv('OPENAI_API_KEY')
    openai_api_key = st.sidebar.text_input(
        'OpenAI API Key', placeholder='sk-', value=openai_api_key_env)
    url = "https://platform.openai.com/account/api-keys"
    st.sidebar.markdown("Get an Open AI Access Key [here](%s). " % url)

    model = st.sidebar.selectbox(
        'Select Model:', ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-1106-preview'])
    uploaded_file = st.sidebar.file_uploader(
        "Upload a Grype JSON file", type=['json'])

    severity_levels = ['Critical', 'High', 'Medium', 'Low']
    selected_severities = {level: st.sidebar.checkbox(
        level, value=level in ['Critical', 'High']) for level in severity_levels}

    with tab0:
        with open("README.md", "r") as readme_file:
            readme_contents = readme_file.read()
            st.markdown(readme_contents)

    with tab1:
        ai_review_instructions = st.text_area(
            "AI Instructions", ai_instructions, height=500)

    with tab2:
        dockerfile = st.text_area("Dockerfile", "", height=500)

    selected_severities_checked = {level for level, checked in selected_severities.items() if checked}

    if st.button("Submit"):
        if uploaded_file is not None and openai_api_key:
            data = json.load(uploaded_file)
            included_fixes = extract_data(data, selected_severities_checked )
            #st.markdown(included_fixes)
            with st.spinner('Working on it...'):
                analysis_result = analyze_cves_with_openai(
                    ai_review_instructions, included_fixes, openai_api_key, dockerfile.strip())
                st.write("Risk and Fixes Analysis:")
                st.markdown(analysis_result)
        else:
            st.warning(
                "Please upload a JSON file and enter OpenAI API key to proceed.")
