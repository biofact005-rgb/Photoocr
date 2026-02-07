import telebot
from PIL import Image
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import io
import os
import re
import random
import string
from stegano import lsb
import pytesseract
import PyPDF2

# ==========================================
# 👇 CONFIGURATION 👇
# ==========================================
# Render par Environment Variable set karna padega 'BOT_TOKEN' naam se
API_TOKEN = os.environ.get('BOT_TOKEN')
if not API_TOKEN:
    print("❌ Error: BOT_TOKEN not found in environment variables!")
    exit()
# ==========================================

bot = telebot.TeleBot(API_TOKEN)
user_data = {}

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

# --- COMPLEXITY CALCULATION ---
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

# --- 4. FEATURE: PASSWORD SHIELD ---

def process_pass_audit(message):
    password = message.text.strip()
    combinations, feedback = calculate_complexity(password)
    
    formatted_combos = "{:.2e}".format(combinations)
    
    if combinations < 10**6: rating = "🔴 Critical (Instant Crack)"
    elif combinations < 10**12: rating = "🟠 Weak (Seconds to Minutes)"
    elif combinations < 10**18: rating = "🟡 Moderate (Days to Years)"
    else: rating = "🟢 Excellent (Centuries)"
    
    report = f"🛡️ **PASSWORD COMPLEXITY REPORT**\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
    report += f"🔑 **Input:** ||{password}||\n\n"
    report += f"📉 **Brute-Force Combinations:**\n👉 **{formatted_combos}** possibilities.\n_(Approx {combinations:,} attempts)_\n\n"
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

    file_info = bot.get_file
