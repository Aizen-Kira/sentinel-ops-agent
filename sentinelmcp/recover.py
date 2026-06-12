import re

log_path = r'C:\Users\Gokul\.gemini\antigravity\brain\8ae27d26-5d2a-4f9b-a830-0857edc12a42\.system_generated\logs\overview.txt'
with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

files_to_recover = [
    'shared/cache.py',
    'realtime/pipeline.py',
    'mcp_server/tools/correlate.py',
    'mcp_server/tools/timeline.py',
    'agent/reporter.py'
]

for target in files_to_recover:
    content = []
    capture = False
    for i, line in enumerate(lines):
        if 'File Path: `file:///' in line and target in line.replace('\\', '/'):
            # This might be a view_file output. 
            # Look for "The following code has been modified..."
            capture = True
            content = []
        elif 'Created file file:///' in line and target in line.replace('\\', '/'):
            # Wait, Created file doesn't have the content after it. The tool input has it.
            # But the tool input is earlier.
            pass
            
        if capture:
            content.append(line)
            if 'The above content shows the entire, complete file contents' in line:
                capture = False

    if content:
        print(f"Found {target} in view_file!")
        # Clean up the line numbers
        cleaned = []
        start_parsing = False
        for c in content:
            if 'The following code has been modified to include a line number' in c:
                start_parsing = True
                continue
            if 'The above content shows the entire, complete file contents' in c:
                break
            if start_parsing:
                # Remove line number: "1: " -> ""
                m = re.match(r'^\d+:\s(.*)$', c)
                if m:
                    cleaned.append(m.group(1))
                else:
                    # Might be an empty line without space
                    m2 = re.match(r'^\d+:$', c.strip())
                    if m2:
                        cleaned.append('')
                    else:
                        cleaned.append(c.strip('\n'))
                        
        with open(target, 'w', encoding='utf-8') as out:
            out.write('\n'.join(cleaned))
        print(f"Recovered {target}")
    else:
        print(f"Could not find view_file output for {target}")
