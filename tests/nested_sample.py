import io
import zipfile

inner_buffer = io.BytesIO()
with zipfile.ZipFile(inner_buffer, "w") as inner:
    inner.writestr("note.txt", b"Harmless text inside the inner archive.")

with zipfile.ZipFile("outer.zip", "w") as outer:
    outer.writestr("inner.zip", inner_buffer.getvalue())

print("Created outer.zip containing a harmless inner.zip.")
