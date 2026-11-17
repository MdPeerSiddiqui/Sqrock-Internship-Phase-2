import os

samples_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
os.makedirs(samples_dir, exist_ok=True)

# 1. Legit PNG
with open(os.path.join(samples_dir, 'legit_image.png'), 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4')

# 2. Spoofed Webshell (.php.png)
with open(os.path.join(samples_dir, 'spoofed_webshell.php.png'), 'wb') as f:
    f.write(b'<?php system($_GET["cmd"]); ?>\n')

# 3. Polyglot Malware (.jpg with valid JPEG header + PHP payload)
with open(os.path.join(samples_dir, 'polyglot_malware.jpg'), 'wb') as f:
    f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00' + b'/* Injected C2 Shell */ <?php eval($_POST["cmd"]); ?>')

# 4. Legit Document (.pdf)
with open(os.path.join(samples_dir, 'legit_document.pdf'), 'wb') as f:
    f.write(b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF')

# 5. Dangerous Executable script (.sh)
with open(os.path.join(samples_dir, 'malicious_script.sh'), 'wb') as f:
    f.write(b'#!/bin/bash\nrm -rf / --no-preserve-root\n')

print("[+] Created 5 sample files in samples directory.")
