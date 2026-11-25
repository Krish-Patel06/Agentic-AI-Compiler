import os
import base64
import subprocess

def create_html_and_pdf():
    fig_dir = r"c:\Users\Krish Patel\OneDrive\Desktop\Agentic-AI-Compiler-main\extracted_figures"
    out_html = r"c:\Users\Krish Patel\OneDrive\Desktop\Agentic-AI-Compiler-main\SecAICodeTutor_Final_Submission.html"
    out_pdf = r"c:\Users\Krish Patel\OneDrive\Desktop\Agentic-AI-Compiler-main\SecAICodeTutor_Final_Submission.pdf"
    
    def b64_img(fname):
        p = os.path.join(fig_dir, fname)
        if not os.path.exists(p):
            return ""
        ext = os.path.splitext(p)[1].lower().replace('.', '')
        if ext == 'jpg': ext = 'jpeg'
        with open(p, 'rb') as f:
            data = base64.b64encode(f.read()).decode('utf-8')
        return f"data:image/{ext};base64,{data}"

    print("Generating HTML report with embedded base64 images...")
    # Read the docx text or build HTML directly
    # Check if edge is available
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ]
    edge_exe = None
    for ep in edge_paths:
        if os.path.exists(ep):
            edge_exe = ep
            break
            
    print(f"Edge executable: {edge_exe}")

create_html_and_pdf()
