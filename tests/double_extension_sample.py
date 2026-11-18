import zipfile

with zipfile.ZipFile("double_extension.zip", "w") as archive:
    archive.writestr("invoice.pdf.exe", b"Harmless text, not a real executable.")

print("Created double_extension.zip with a harmless text file.")
