import os
import shutil

src = r'c:\Users\Krish Patel\OneDrive\Desktop\Agentic-AI-Compiler-main'
dest = r'c:\Users\Krish Patel\OneDrive\Desktop\Agentic-AI-Compiler-main-backup'

print(f"Duplicating workspace from:\n  {src}\nto:\n  {dest}")

# Use robocopy via os.system
cmd = f'robocopy "{src}" "{dest}" /E /XD __pycache__ /R:1 /W:1'
ret = os.system(cmd)
# robocopy exit codes 0-7 mean success
print(f"Robocopy finished with code {ret}")

if ret <= 7:
    total_files = sum(len(files) for _, _, files in os.walk(dest))
    print(f"Backup created successfully! Total files in backup: {total_files}")
else:
    print(f"Robocopy encountered an error: {ret}")
