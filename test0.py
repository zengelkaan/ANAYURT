from flask import Flask, request, jsonify 
from flask_cors import CORS
from dotenv import load_dotenv
import os
import sqlite3 # Veritabanı işlemleri için, chat geçmişini saklamak için kullanılacak, bağlama uygun cevaplar vermesi için
import json
from openai import OpenAI
from langdetect import detect

# Ortam değişkenlerini yükle
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Flask uygulaması
app = Flask(__name__)

CORS(app)

DB_PATH = "chat_sessions.db" # Konuşma geçmişini saklamak için kullanılacak SQLite veritabanı dosyası

#print(os.getenv("OPENAI_API_KEY")) #api kontrolu için, env dosyasından alıyor mu diye

def init_db(): # Veritabanını başlat
    conn = sqlite3.connect(DB_PATH) # Veritabanına bağlanır, conn = connection, özel bir ad değil
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç, cursor oluşturur, c = cursor, özel bir ad değil, veritabanı bağlantısı üzerinden işlem yapmak için kullanılır
    c.execute(''' 
        CREATE TABLE IF NOT EXISTS chat_history ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''') # chat_history adında bir tablo oluşturur, session_id, role (user, assistant), message (kullanıcı mesajı, bot cevabı), timestamp (mesajın zamanı) alanlarını içerir.
    conn.commit() # Değişiklikleri kaydeder
    conn.close() # Veritabanı bağlantısını kapatır

init_db() # Uygulama başlatıldığında veritabanını başlatır

# Mesaj kaydet
def save_message(session_id, role, message): # Veritabanına mesaj kaydeder
    conn = sqlite3.connect(DB_PATH) # Veritabanına bağlanır
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç oluşturur
    c.execute("INSERT INTO chat_history (session_id, role, message) VALUES (?, ?, ?)",
              (session_id, role, message)) # chat_history tablosuna yeni bir kayıt ekler, session_id, role (user veya assistant), message (kullanıcı mesajı veya bot cevabı) alanlarını kullanır.
    conn.commit() # Değişiklikleri kaydeder
    conn.close() # Veritabanı bağlantısını kapatır


def get_history_pairs(session_id): # Veritabanından geçmiş mesajları alır, belirli session_id için user ve assistant mesajlarını çiftler halinde döndürür
    conn = sqlite3.connect(DB_PATH) # Veritabanına bağlanır
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç, cursor oluşturur
    c.execute("SELECT role, message FROM chat_history WHERE session_id = ? ORDER BY id ASC", (session_id,)) # chat_history tablosundan belirtilen session_id için role (user veya assistant) ve message (kullanıcı mesajı veya bot cevabı) alanlarını alır, id'ye göre artan sırada sıralar
    rows = c.fetchall() # Tüm satırları alır
    conn.close() # Veritabanı bağlantısını kapatır

    pairs = [] # Mesaj çiftlerini saklamak için boş bir liste oluşturur
    i = 0 # İndeks değişkeni, satırları döngüde gezmek için kullanılır
    while i < len(rows) - 1: # Satırların sonuna gelene kadar döngü devam eder
        if rows[i][0] == "user" and rows[i+1][0] == "assistant": # Eğer şu anki satırın role'u "user" ve bir sonraki satırın role'u "assistant" ise
            pairs.append((rows[i][1], rows[i+1][1])) # Bu iki mesajı çift olarak listeye ekler
            i += 2 # İki satırı atlar, çünkü bir kullanıcı mesajı ve ona karşılık gelen bot cevabı zaten çift olarak eklendi
        else:
            i += 1 # Eğer şu anki satırın role'u "user" değilse veya bir sonraki satırın role'u "assistant" değilse, sadece bir satırı atlar
    return pairs # Mesaj çiftlerini döndürür

class ProfessionAgent: # Meslek bazlı agent sınıfı
    def __init__(self, profession_name, system_prompt, context_file): # Agent'ın başlatılması için gerekli parametreler
        self.profession_name = profession_name # Meslek adı
        self.system_prompt = system_prompt # Sistem promptu, agent'ın nasıl davranması gerektiğini belirler
        self.context_file = context_file # Bağlam dosyası, agent'ın kullanacağı ek bilgi

    def get_context(self): # Bağlam bilgisini dosyadan alır
        try: 
            with open(self.context_file, 'r', encoding='utf-8') as f: # Bağlam dosyasını okur
                data = json.load(f) # JSON formatındaki veriyi yükler
            
            lines = [] # Satırları saklamak için boş bir liste oluşturur

            for key, value in data.items(): # JSON verisindeki her anahtar-değer çifti için
                line = f"{key}: {value}" # Anahtar-değer çiftini "anahtar: değer" formatında bir satır olarak oluşturur
                lines.append(line) # Satırı listeye ekler
                result = "\n".join(lines) # Her anahtar-değer çiftini bir satır olarak birleştirir
            return result # Bağlam bilgisini döndürür
        
        except FileNotFoundError: # Eğer bağlam dosyası bulunamazsa
            return "No context data available."   # Hata mesajı döndürür, bağlam verisi yoksa

    def respond(self, user_message, history): # Kullanıcı mesajına yanıt verir, geçmiş mesajları kullanarak
        context = self.get_context() # Bağlam bilgisini alır
        messages = [{
            "role": "system",
            "content": f"{self.system_prompt}\n\nContext Information:\n{context}\n\nPlease respond in the same language as the user's message."
        }]
        for user_msg, assistant_msg in history: # Geçmiş mesajları ekler
            messages.append({"role": "user", "content": user_msg} ) # Geçmişteki kullanıcı mesajını ekler
            messages.append({"role": "assistant", "content": assistant_msg}) # Geçmişteki bot cevabını ekler
        messages.append({"role": "user", "content": user_message}) # Şu anki kullanıcı mesajını ekler

        response = client.chat.completions.create( # OpenAI API'sine istek gönderir
            model="gpt-4o",
            messages=messages,
            temperature=0.7
        )
        return response.choices[0].message.content.strip() # API'den gelen cevabı alır ve temizler, boşlukları kaldırır

# Meslek agent'ları
agents = {
    "dentist": ProfessionAgent(
        profession_name="Dentist",
        system_prompt="""You are a professional dentist assistant. You help patients with dental-related questions and concerns. 
        You should provide accurate, helpful information based on the context provided. 
        Always respond in a professional and caring manner.""",
        context_file="db/dentist.json"
    ),
    "hairdresser": ProfessionAgent(
        profession_name="Hairdresser", 
        system_prompt="""You are a professional hairdresser assistant. You help clients with hair-related questions and services.
        You should provide helpful information about hair care, styling, and services based on the context provided.
        Always respond in a friendly and professional manner.""",
        context_file="db/hairdresser.json"
    ),
    "trainer": ProfessionAgent(
        profession_name="Personal Trainer",
        system_prompt="""You are a professional personal trainer assistant. You help clients with fitness and training-related questions.
        You should provide helpful information about exercises, nutrition, and fitness programs based on the context provided.
        Always respond in an encouraging and motivational manner.""",
        context_file="db/trainer.json"
    )
}

def detect_profession_with_llm(user_message, lang, previous_message = None): # Meslek tespiti için LLM kullanır

    if previous_message :
        previous_context = f"Previous message: {previous_message} \n"
    
    else :
        previous_context = ""

    prompt = f"""
        You have 3 options: dentist, hairdresser, trainer.
        Your task is to detect which profession the user's message relates to.
        Use the user's current message and, if available, the previous message for context: {previous_context}.
        Return ONLY ONE of these exact words: dentist, hairdresser, trainer.

        Current message (in {lang}): {user_message}
        """ # Mesajın hangi meslekle ilgili olduğunu tespit etmek için prompt oluşturur, sistem promptu
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0
    )
    profession = response.choices[0].message.content.strip().lower()

    if profession in agents:
        return profession 
    else:
        return "unknown"

@app.route("/chat", methods=["POST"]) # Chat endpointi, kullanıcı mesajını alır ve ilgili meslek agent'ını çağırır
def chat():
    data = request.get_json() # JSON formatında gelen veriyi alır
    session_id = data.get("session_id") # Oturum ID'sini alır, bu ID ile geçmiş mesajları saklar
    user_message = data.get("message", "") # Kullanıcı mesajını alır, eğer mesaj yoksa boş string olarak ayarlar 

    if not session_id or not user_message: # Eğer session_id veya message yoksa hata döndürür
        return jsonify({"error": "session_id and message are required"})

    lang = detect(user_message)

    history = get_history_pairs(session_id) # Geçmiş mesajları alır, session_id ile eşleşen tüm user ve assistant mesajlarını çiftler halinde döndürür
    
    if history:
        last_user_msg = history[-1][0]
        user_message = f"In continuation of: '{last_user_msg}'\n{user_message}"

    else :
        last_user_msg = ""

    profession = detect_profession_with_llm(user_message, lang, last_user_msg) # Kullanıcı mesajının hangi meslekle ilgili olduğunu tespit eder
    if profession == "unknown":
        return jsonify({
            "response": "Sorry, I couldn't understand which profession this is related to.",
            "profession": profession,
            "language": lang
        })

    agent = agents[profession] # Tespit edilen meslek agent'ını alır
    bot_reply = agent.respond(user_message, history) # Agent'ın respond metodunu çağırarak kullanıcı mesajına yanıt alır

    save_message(session_id, "user", user_message) # Kullanıcı mesajını veritabanına kaydeder
    save_message(session_id, "assistant", bot_reply)   # Bot cevabını veritabanına kaydeder

    return jsonify({ 
        "response": bot_reply,
        "profession": profession,
        "language": lang
    })


@app.route("/history", methods=["GET"]) # Geçmiş mesajları almak için endpoint
def history(): 
    session_id = request.args.get("session_id") # URL parametresinden session_id alır
    if not session_id: # Eğer session_id yoksa hata döndürür
        return jsonify({"error": "session_id is required"})

    history = get_history_pairs(session_id) # Geçmiş mesajları alır, session_id ile eşleşen tüm user ve assistant mesajlarını çiftler halinde döndürür
    formatted = [{"user": user_msg, "assistant": assistant_msg} for user_msg, assistant_msg in history]
    return jsonify({"history": formatted})

if __name__ == "__main__":
    app.run(debug=True)
