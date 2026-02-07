import telebot
from PIL import Image, ExifTags
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import io
import os
import re
import random
import string
import threading
from flask import Flask  # <--- Render ke liye zaroori hai
from stegano import lsb
import pytesseract
import PyPDF2

# ==========================================
# 👇 CONFIGURATION 👇
# ==========================================
# Render par Environment Variable 'BOT_TOKEN' set karein
API_TOKEN = os.environ.get('BOT_TOKEN')

# Local Testing ke liye (Agar render par nahi ho toh ise uncomment karo)
# API_TOKEN = "YOUR_TOKEN_HERE" 

if not API_TOKEN:
    print("❌ Error: BOT_TOKEN not found! (Check Render Environment Variables)")

bot = telebot.TeleBot(API_TOKEN) if API_TOKEN else None

# ==========================================
# 🌐 FAKE WEB SERVER (RENDER KEEP-ALIVE)
# ==========================================
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 Spy Bot V6 is Running Live!"

def run_server():
    # Render automatically PORT env variable deta hai
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

def keep_alive():
    t = threading.Thread(target=run_server)
    t.start()

print("✅ Professional Forensics Bot V6 (Render Version) Online...")

# --- 1. HELPER FUNCTIONS ---

def get_decimal_from_dms(dms, ref):
    try:
        degrees = dms[0]; minutes = dms[1]; seconds = dms[2]
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ['S', 'W']: decimal = -decimal
        return decimal
    except: return None

def get_gps_coords(exif):
    gps_info = exif.get(34853)
    if not gps_info: return None
    try:
        lat_ref = gps_info.get(1); lat_dms = gps_info.get(2)
        lon_ref = gps_info.get(3); lon_dms = gps_info.get(4)
        if lat_ref and lat_dms and lon_ref and lon_dms:
            return get_decimal_from_dms(lat_dms, lat_ref), get_decimal_from_dms(lon_dms, lon_ref)
    except: return None
    return None

def format_pdf_date(date_str):
    if not date_str: return "Unknown"
    return date_str.replace("D:", "").replace("'", "")

# --- COMPLEXITY CALCULATION (MATHS) ---
def calculate_complexity(password):
    pool_size = 0
    # Logic: Har type ke character se pool badhta hai
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"\d", password): pool_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): pool_size += 32
    
    if pool_size == 0: return 0, []

    # Formula: Combinations = Pool_Size ^ Length
    length = len(password)
    combinations = pool_size ** length
    
    feedback = []
    if length < 8: feedback.append("- Length is critical (increase to 12+)")
    if not re.search(r"[A-Z]", password): feedback.append("- Add Uppercase letters (A-Z)")
    if not re.search(r"\d", password): feedback.append("- Add Numbers (0-9)")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): feedback.append("- Add Symbols (!@#$)")

    return combinations, feedback

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for i in range(length))

# --- 2. START & MENU ---

@bot.message_handler(commands=['start'])
def welcome(message):
    markup = InlineKeyboardMarkup()
    markup.row_width = 1
    
    btn1 = InlineKeyboardButton("🔐 Encrypt Image (Hide Data)", callback_data="mode_hide")
    btn2 = InlineKeyboardButton("🕵️ Analyze Image (Forensics)", callback_data="mode_scan")
    btn3 = InlineKeyboardButton("📄 Analyze PDF (Metadata)", callback_data="mode_pdf")
    btn4 = InlineKeyboardButton("🛡️ Password Shield (Complexity)", callback_data="mode_pass")
    
    markup.add(btn1, btn2, btn3, btn4)
    
    welcome_text = (
        "🤖 **Cyber Intelligence Interface V6**\n\n"
        "Welcome, Agent. Select an operation module below:\n"
    )
    bot.reply_to(message, welcome_text, reply_markup=markup, parse_mode="Markdown")

# --- 3. BUTTON HANDLER ---

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == "mode_hide":
        msg = bot.send_message(call.message.chat.id, "📸 **Encryption Module:**\nPlease upload the **Image** (as Document) to hide secret data.")
        bot.register_next_step_handler(msg, process_photo_for_hiding)
        
    elif call.data == "mode_scan":
        msg = bot.send_message(call.message.chat.id, "🕵️ **Image Analysis Module:**\nUpload a Photo/Document. System will scan for GPS, Metadata & Hidden Text.")
        bot.register_next_step_handler(msg, process_scan)
        
    elif call.data == "mode_pdf":
        msg = bot.send_message(call.message.chat.id, "📄 **PDF Forensics Module:**\nUpload a PDF document to extract authorship metadata.")
        bot.register_next_step_handler(msg, process_pdf_analysis)

    elif call.data == "mode_pass":
        markup = InlineKeyboardMarkup()
        markup.row_width = 1
        btn_audit = InlineKeyboardButton("🔍 Check Password Combinations", callback_data="sub_audit")
        btn_gen = InlineKeyboardButton("⚡ Generate Secure Password", callback_data="sub_gen")
        markup.add(btn_audit, btn_gen)
        bot.send_message(call.message.chat.id, "🛡️ **Password Shield Module:**\nSelect an action:", reply_markup=markup)

    elif call.data == "sub_audit":
        msg = bot.send_message(call.message.chat.id, "🔍 **Complexity Audit:**\nSend the password you want to analyze.")
        bot.register_next_step_handler(msg, process_pass_audit)

    elif call.data == "sub_gen":
        password = generate_strong_password()
        bot.send_message(call.message.chat.id, f"⚡ **Generated Secure Password:**\n\n<code>{password}</code>\n\n(Click to copy)", parse_mode="HTML")

# --- 4. FEATURE: PASSWORD SHIELD (MATHS LOGIC) ---

def process_pass_audit(message):
    password = message.text.strip()
    combinations, feedback = calculate_complexity(password)
    
    # Scientific Notation (e.g., 3.45e+12)
    formatted_combos = "{:.2e}".format(combinations)
    
    if combinations < 10**6: rating = "🔴 Critical (Instant Crack)"
    elif combinations < 10**12: rating = "🟠 Weak (Seconds to Minutes)"
    elif combinations < 10**18: rating = "🟡 Moderate (Days to Years)"
    else: rating = "🟢 Excellent (Centuries)"
    
    report = f"🛡️ **PASSWORD COMPLEXITY REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
    report += f"🔑 **Input:** ||{password}||\n\n"
    report += f"📉 **Brute-Force Combinations:**\nTo crack this, an attacker needs:\n👉 **{formatted_combos}** tries.\n_(Approx {combinations:,} attempts)_\n\n"
    report += f"📊 **Security Rating:**\n{rating}\n\n"
    
    if feedback:
        report += "⚠️ **Improvement Strategy:**\n" + "\n".join(feedback)
    else:
        report += "✅ **Status:** Maximum Entropy Achieved."
        
    bot.reply_to(message, report, parse_mode="Markdown")

# --- 5. FEATURE: HIDE SECRET MESSAGE ---

def process_photo_for_hiding(message):
    if not message.photo and not message.document:
        bot.reply_to(message, "⚠️ Error: Invalid file. Please upload an image.")
        return

    if message.document: file_id = message.document.file_id
    else: file_id = message.photo[-1].file_id

    file_info = bot.get_file(file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    temp_filename = f"temp_{message.chat.id}.png"
    with open(temp_filename, 'wb') as new_file: new_file.write(downloaded_file)
    
    img = Image.open(temp_filename)
    img.save(temp_filename)

    user_data[message.chat.id] = {'file_path': temp_filename}
    msg = bot.reply_to(message, "📝 **Input Required:**\nEnter text to hide.")
    bot.register_next_step_handler(msg, process_text_hiding)

def process_text_hiding(message):
    try:
        chat_id = message.chat.id
        secret_text = message.text
        file_path = user_data[chat_id]['file_path']
        
        status = bot.reply_to(message, "⚙️ **Processing:** Encryption in progress...")
        
        secret_img = lsb.hide(file_path, secret_text)
        output_filename = f"secure_data_{chat_id}.png"
        secret_img.save(output_filename)
        
        with open(output_filename, "rb") as f:
            bot.send_document(chat_id, f, caption="✅ **Encryption Complete.**")
            
        os.remove(file_path); os.remove(output_filename)
        bot.delete_message(chat_id, status.message_id)
    except: bot.reply_to(message, "❌ Error: Image too small or format issue.")

# --- 6. FEATURE: IMAGE SCAN (OCR & GPS) ---

def process_scan(message):
    try:
        status_msg = bot.reply_to(message, "⚙️ **Processing:** Deep scanning...")
        if message.document: file_id = message.document.file_id
        elif message.photo: file_id = message.photo[-1].file_id
        else: return

        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        img_stream = io.BytesIO(downloaded_file)
        image = Image.open(img_stream)
        
        report = "🕵️‍♂️ **FORENSIC ANALYSIS REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"

        # Device Metadata
        exif_data = image._getexif()
        if exif_data:
            make = exif_data.get(271, "N/A"); model = exif_data.get(272, "Unknown")
            date = exif_data.get(306, "Unknown")
            report += f"📱 **[ DEVICE METADATA ]**\nModel: {make} {model}\nTime: {date}\n\n"
        else: report += "📱 **[ DEVICE METADATA ]**\nStatus: No EXIF data.\n\n"

        # Hidden Message Check
        try:
            temp_scan = f"scan_{message.chat.id}.png"
            with open(temp_scan, 'wb') as f: f.write(downloaded_file)
            hidden_msg = lsb.reveal(temp_scan)
            os.remove(temp_scan)
            if hidden_msg: report += f"🔓 **[ HIDDEN DATA ]**\n<code>{hidden_msg}</code>\n\n"
            else: report += "🔒 **[ HIDDEN DATA ]**\nNegative.\n\n"
        except: report += "🔒 **[ HIDDEN DATA ]**\nNegative.\n\n"

        # GPS Check
        if exif_data:
            coords = get_gps_coords(exif_data)
            if coords:
                lat, lon = coords
                report += f"📍 **[ GEOLOCATION ]**\n<a href='http://maps.google.com/0{lat},{lon}'>Open Satellite View</a>\n\n"
            else: report += "📍 **[ GEOLOCATION ]**\nNo GPS tags.\n\n"
        else: report += "📍 **[ GEOLOCATION ]**\nNo GPS tags.\n\n"

        # OCR Check
        try:
            extracted_text = pytesseract.image_to_string(image)
            if len(extracted_text.strip()) > 5:
                report += f"📝 **[ OCR TEXT ]**\n<code>{extracted_text[:300]}</code>\n"
            else: report += "📝 **[ OCR TEXT ]**\nNo readable text detected.\n"
        except: pass

        report += "━━━━━━━━━━━━━━━━━━━━━━━━"
        bot.edit_message_text(report, message.chat.id, status_msg.message_id, parse_mode="HTML", disable_web_page_preview=True)
    except Exception as e: bot.reply_to(message, f"❌ Error: {e}")

# --- 7. FEATURE: PDF FORENSICS ---

def process_pdf_analysis(message):
    try:
        if not message.document or 'pdf' not in message.document.mime_type:
            bot.reply_to(message, "⚠️ **Invalid:** Please upload a PDF.")
            return

        status_msg = bot.reply_to(message, "⚙️ **Processing:** Parsing PDF...")
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        pdf_file = io.BytesIO(downloaded_file)
        reader = PyPDF2.PdfReader(pdf_file)
        meta = reader.metadata

        report = "📄 **DOCUMENT FORENSICS REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
        if meta:
            report += f"👤 **Author:** {meta.get('/Author', 'Unknown')}\n"
            report += f"🛠️ **Creator:** {meta.get('/Creator', 'Unknown')}\n"
            report += f"📅 **Created:** {format_pdf_date(meta.get('/CreationDate', 'Unknown'))}\n"
            report += f"✏️ **Modified:** {format_pdf_date(meta.get('/ModDate', 'Unknown'))}\n"
            report += f"📑 **Pages:** {len(reader.pages)}\n"
        else: report += "⚠️ No metadata found."
        
        report += "━━━━━━━━━━━━━━━━━━━━━━━━"
        bot.edit_message_text(report, message.chat.id, status_msg.message_id, parse_mode="HTML")
    except Exception as e: bot.reply_to(message, f"❌ PDF Error: {e}")

# --- START SERVER AND BOT ---
if __name__ == "__main__":
    keep_alive()  # <--- Ye fake server chalu karega
    if bot:
        bot.infinity_polling()
