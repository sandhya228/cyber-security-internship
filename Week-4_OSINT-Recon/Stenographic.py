from PIL import Image
import hashlib

def get_file_hash(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def embed_hash_in_image(cover_image, output_image, hash_str):
    img = Image.open(cover_image)
    binary_hash = ''.join(format(ord(c), '08b') for c in hash_str)  

    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = img.load()

    width, height = img.size
    total_pixels = width * height
    if len(binary_hash) > total_pixels * 3:
        raise ValueError("Cover image too small to embed the hash")

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index >= len(binary_hash):
                break
            r, g, b = pixels[x, y]
        
            if data_index < len(binary_hash):
                r = (r & ~1) | int(binary_hash[data_index]); data_index += 1
            if data_index < len(binary_hash):
                g = (g & ~1) | int(binary_hash[data_index]); data_index += 1
            if data_index < len(binary_hash):
                b = (b & ~1) | int(binary_hash[data_index]); data_index += 1
            pixels[x, y] = (r, g, b)
        if data_index >= len(binary_hash):
            break

    img.save(output_image)
    print(f"[+] Hash embedded into {output_image}")


def extract_hash_from_image(stego_image, hash_length=64):  # 64 hex chars for SHA256
    img = Image.open(stego_image)
    pixels = img.load()
    width, height = img.size

    binary_hash = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_hash += str(r & 1)
            binary_hash += str(g & 1)
            binary_hash += str(b & 1)
            if len(binary_hash) >= hash_length * 8:
                break
        if len(binary_hash) >= hash_length * 8:
            break

    chars = [binary_hash[i:i+8] for i in range(0, len(binary_hash), 8)]
    extracted_hash = ''.join(chr(int(c, 2)) for c in chars)
    return extracted_hash[:hash_length]


def verify_file_integrity(file_to_check, stego_image):
    current_hash = get_file_hash(file_to_check)
    hidden_hash = extract_hash_from_image(stego_image)

    print(f"Current File Hash : {current_hash}")
    print(f"Extracted Hash    : {hidden_hash}")

    if current_hash == hidden_hash:
        print("[+] File is INTACT (No modification detected)")
    else:
        print("[!] File has been MODIFIED")


if __name__ == "__main__":
    file = "report.pdf"  
    cover_img = "cover.png"  
    stego_img = "stego_output.png"

    hash_str = get_file_hash(file)
    print("[*] Generated File Hash:", hash_str)

    embed_hash_in_image(cover_img, stego_img, hash_str)

    verify_file_integrity(file, stego_img)
