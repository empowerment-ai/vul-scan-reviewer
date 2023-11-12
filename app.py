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


def prepare_vulnerability_data(vulnerabilities, severities):
    filtered_vulnerabilities = [
        vul for vul in vulnerabilities if vul['severity'] in severities]

    data_for_table = []
    cves_to_analyze = set()  # Using a set to avoid duplicates
    for vul in filtered_vulnerabilities:
        cve = vul['identifiers'][0]['value'] if 'identifiers' in vul and vul['identifiers'] else 'N/A'
        link = vul['links'][0]['url'] if 'links' in vul and vul['links'] else 'N/A'
        solution = vul['solution'] if 'solution' in vul else 'No solution provided'
        source = vul['location']['image'] if 'location' in vul and 'image' in vul['location'] else 'N/A'
        severity = vul['severity'] if 'severity' in vul else 'N/A'

        data_for_table.append({
            "Source": source,
            "Severity": severity,
            "CVE": cve,
            "Details Link": link,
            "Solution": solution
        })

        if solution and solution != 'No solution provided':
            cves_to_analyze.add(cve)  # Adding to a set ensures no duplicates

    # Converting back to a list for further processing
    return data_for_table, list(cves_to_analyze)


def get_remediations(llm, cves, dockerfile):
    remediation_instructions = """I want you to act as an expert on docker and how to remediate vulnerabilities. 
        Given the following CVEs, I want you to suggest changes to the provided Dockerfile to remediate or fix the CVEs. 
        CVEs: {cves}
        DOCKERFILE:
           {dockerfile}
           """

    input_variables = ["cves", "dockerfile"]

    prompt_template = PromptTemplate(
        input_variables=input_variables, template=remediation_instructions)
    rem_chain = LLMChain(llm=llm, prompt=prompt_template,
                         output_key="remediations")
    remediations = rem_chain.run({'cves': cves, 'dockerfile': dockerfile})
    return remediations


# Function to analyze CVEs using LangChain and OpenAI
def analyze_cves_with_openai(ai_instructions, cves, table, openai_api_key, dockerfile):
    cves_string = ','.join(cves)
    remediations = ""
    # return cves_string
    with get_openai_callback() as cb:
        llm = ChatOpenAI(model_name=model, temperature=0.0,
                         openai_api_key=openai_api_key)
        input_variables = ["cves", "table"]
        prompt_template = PromptTemplate(
            input_variables=input_variables, template=ai_instructions)
        review_chain = LLMChain(
            llm=llm, prompt=prompt_template, output_key="feedback")
        feedback = review_chain.run({'cves': cves_string, 'table': table})
        print(cb)
        # print (cves_string)

        if dockerfile:
            remediations = get_remediations(llm, cves_string, dockerfile)

    return f"""
        {feedback}
       
        {remediations}
        """


if __name__ == '__main__':

    ai_instructions = """
    
    Act as an expert on Information Assurance and docker containers vulnerabilities.  

    Provide a summary feedback for the following CVEs: {cves}. Return output using markdown and provide links if possible. 
    You can use the following table to help with providing details about where to get more info and recommended fixes: {table}. 
  
Here is a sample output that I want you to use as a template for all responses.  Do not deviate from this format:

Source	Severity	CVE	Details Link	Solution
your_custom_image	High	CVE-2018-0732	Details	Upgrade to a non-vulnerable version of OpenSSL.
Summary Feedback:

The detected vulnerability is CVE-2018-0732, which has a high severity. This vulnerability affects your_custom_image.

For more details about this vulnerability, you can refer to the Details Link.

The recommended solution to address this vulnerability is to upgrade to a non-vulnerable version of OpenSSL.

Detected Issue Counts by Severity:

Based on the provided information, there is only one detected vulnerability with a severity level of High. No critical findings were mentioned.

Recommendation:

Considering the presence of a high-severity vulnerability, it is recommended to address and fix this vulnerability before approving the system for production use.
    
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

    if st.button("Submit"):
        if uploaded_file is not None and openai_api_key:
            data = json.load(uploaded_file)
            active_severities = [
                level for level, checked in selected_severities.items() if checked]
            vulnerabilities_data, cves_to_analyze = prepare_vulnerability_data(
                data['vulnerabilities'], active_severities)

            # Display the table
            df = pd.DataFrame(vulnerabilities_data)
            # st.table(df)

            # Analyze CVEs using OpenAI
            if cves_to_analyze:
                with st.spinner('Working on it...'):
                    analysis_result = analyze_cves_with_openai(
                        ai_review_instructions, cves_to_analyze, df, openai_api_key, dockerfile.strip())
                    st.write("Risk and Fixes Analysis:")
                    st.markdown(analysis_result)
                    # if dockerfile.strip():  # Checks if dockerfile is not just empty or whitespace
                    #     with st.spinner('Looking for Remediations...'):
                    #         # Logic to handle Dockerfile
                    #         st.write('Dockerfile is present. Here is the content:')
                    #         st.text(dockerfile)
            else:
                active_severities_string = ", ".join(
                    level for level, checked in selected_severities.items() if checked)
                if active_severities_string:
                    st.write(
                        f"This scan appears to not have any valid open findings for selected severities: {active_severities_string}.")
                else:
                    st.write(
                        "This scan appears to not have any valid open findings.")
        else:
            st.warning(
                "Please upload a JSON file and enter OpenAI API key to proceed.")
