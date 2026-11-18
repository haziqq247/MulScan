import zipfile

data = b"A" * (2 * 1024 * 1024)

with zipfile.ZipFile(
    "compression_test.zip", "w", compression=zipfile.ZIP_DEFLATED
) as archive:
    archive.writestr("repeated_text.txt", data)

print("Created compression_test.zip with 2 MiB of harmless text.")
