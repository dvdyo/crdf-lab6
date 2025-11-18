import argparse
import io
import zipfile
import tempfile
from pathlib import Path

from docx import Document
from PIL import Image
import numpy as np

def transform_image_on_disk(image_path: Path):
    try:
        img = Image.open(image_path).convert("RGB")
        
        img_array = np.array(img)
        noise = np.random.randint(-40, 40, img_array.shape, dtype='int16')
        noisy_array = np.clip(img_array + noise, 0, 255).astype('uint8')
        noisy_img = Image.fromarray(noisy_array)

        jpeg_buffer = io.BytesIO()
        noisy_img.save(jpeg_buffer, format="JPEG", quality=75)
        jpeg_buffer.seek(0)
        reencoded_img = Image.open(jpeg_buffer)

        reencoded_img.save(image_path, format="BMP")
        
        print(f"[*] Transformed image: {image_path.name}")
    except Exception as e:
        print(f"[!] Warning: Could not process {image_path.name}. Error: {e}")

def process_docx(input_path: Path, output_path: Path):
    doc = Document(input_path)
    image_paths_in_docx = [
        rel.target_part.partname.lstrip('/')
        for rel in doc.part.rels.values()
        if "image" in rel.target_ref
    ]

    if not image_paths_in_docx:
        print("[*] No images found.")
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        with zipfile.ZipFile(input_path, 'r') as zip_ref:
            zip_ref.extractall(temp_path)
        
        for internal_path in image_paths_in_docx:
            transform_image_on_disk(temp_path / internal_path)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_out.write(file_path, arcname)

def main():
    parser = argparse.ArgumentParser(
        description="Aggressively modify images in a .docx file using a hybrid approach."
    )
    parser.add_argument("input_file", help="The original .docx file.")
    parser.add_argument("output_file", help="The path for the modified .docx file.")
    args = parser.parse_args()

    try:
        process_docx(Path(args.input_file), Path(args.output_file))
        print(f"\n[SUCCESS] Jammed document saved to: {args.output_file}")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        exit(1)

if __name__ == "__main__":
    main()
