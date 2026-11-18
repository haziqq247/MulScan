import zipfile

with zipfile.ZipFile("header_test.zip", "w") as archive:
    archive.writestr(
        "photo.jpg",
        b"MZ - harmless text for testing header detection."
    )

print("Created header_test.zip")
