# AI-based Container Vulnerability Scan Reviewer

Welcome to this AI-powered tool designed to assist in reviewing a grype or trivy container scan and dockerfile. This application utilizes the capabilities of [LangChain](https://github.com/LangChain/langchain) and [OpenAI](https://openai.com) to automate the review process. This tool currently requires an OpenAI API Key, which can be obtained using the provided link.   While it is not free, the OpenAI models provide the best results and overall the [cost](https://openai.com/pricing#language-models) per check is minimal.  Rever to the OpenAI website for details.

## How it Works
The tool parses the scan results json file and dockerfile against specified criteria. By integrating LangChain and OpenAI, we can leverage advanced natural language processing to provide remediation recommendations.

## Features
- **Look for CVE recommendations**:  Evaluate scan against known CVE fixes and best practices.
- **Feedback Generation**: Automatically generate constructive feedback based on the scan analysis.

## Get Started
To begin, simply review or tweak the AI instructions, upload your grype/trivy json file and dockerfile. Once you are done, you can click the Submit button to evaluate the scan.

## Caveats
This does not replace the need for an expert review of the scan.  While the plan is to improve this tool, AI will generate hallucinations from time to time. Having said that, you may need to tweak the AI instructions to improve the generated feedback.        

## Useful Links
- [Streamlit Documentation](https://docs.streamlit.io)
- [OpenAI API Documentation](https://beta.openai.com/docs/)
- [LangChain API Documentation](https://python.langchain.com/docs/get_started/introduction)
- [Source Code](https://github.com/empowerment-ai/vul-scan-reviewer)

Feel free to explore the code and contribute to the project. Your feedback and contributions are most welcome!

---
