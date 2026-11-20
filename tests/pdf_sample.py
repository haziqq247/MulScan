"""harmless test PDF for MulScan.

The file only contains the PDF action *keywords* that Analyzer B searches for,
so the detection rules can be tested safely.
Run it from inside samples/ so the file stays in the authorized scope:
    cd samples
    python ../tests/pdf_sample.py
"""

content = (
    b"%PDF-1.4\n"
    b"% Harmless test file for MulScan. It does nothing when opened.\n"
    b"/OpenAction\n"
    b"/JavaScript\n"
    b"/Launch\n"
)

with open("pdf_test.pdf", "wb") as pdf_file:
    pdf_file.write(content)

print("Created pdf_test.pdf with harmless PDF action keywords.")