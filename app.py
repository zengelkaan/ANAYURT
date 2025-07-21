from flask import Flask, request, jsonify 
from flask_cors import CORS
from dotenv import load_dotenv
import os
import sqlite3
import json
from openai import OpenAI
from langdetect import detect
import jwt
import uuid
import hashlib

# Ortam değişkenlerini yükle
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

JWT_KEY = os.getenv("JWT_KEY")
JWT_ALGORITHM = "HS256" # Algoritma belirlendi.

# Flask uygulaması
app = Flask(__name__)
CORS(app, supports_credentials=True, origins="*")

# Her meslek için ayrı veritabanı dosyası
DB_PATHS = {
    "dentist": "chat_sessions_dentist.db", 
    "hairdresser": "chat_sessions_hairdresser.db", 
    "trainer": "chat_sessions_trainer.db"
}

# Kullanıcı veritabanı
USERS_DB = "users.db" 

def init_users_db(): # Kullanıcı veri tabanını başlatıyoruz
    conn = sqlite3.connect(USERS_DB) # Veritabanına bağlanır, conn = connection, özel bir ad değil
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç, cursor oluşturur, c = cursor, özel bir ad değil, veritabanı bağlantısı üzerinden işlem yapmak için kullanılır
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profession TEXT NOT NULL
        )
    ''') # users adında bir tablo oluşturur, id, username, passwordhash ve profession alanlarını içerir.
    conn.commit() # Değişiklikleri kaydeder
    conn.close() # Veritabanı bağlantısını kapatır

def hash_password(password): 
    return hashlib.sha256(password.encode()).hexdigest() 
#.encode(): Şifreyi bytes tipine çevirir.
#hashlib.sha256(): Girilen metni sabit uzunlukta bir stringe dönüştrür. Tek yönlü bir işlemdir şifre tekrar elde edilemez.
#hexdigest(): Gelen kodu hexadecimal stringe çevirir.
# Örn: "parolam123" → 'fbb4a8a163ffa958b4f02bf9cabb30cfefb40de803f2c4c346a9d39b3be1b544'



def verify_password(password, password_hash): 
    return hash_password(password) == password_hash #Kullanıcının girdiği şifreyi tekrar aynı şekilde hash'leyip, veritabanındaki hash ile karşılaştırıyoruz.

def init_db(profession): 
    db_path = DB_PATHS[profession] # Hangi profession ise o db'yi bul.
    conn = sqlite3.connect(db_path) # Veritabanına bağlanır, conn = connection, özel bir ad değil
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç, cursor oluşturur, c = cursor, özel bir ad değil, veritabanı bağlantısı üzerinden işlem yapmak için kullanılır
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''') # chat_history adında bir tablo oluşturur, session_id, role (user, assistant) ve message (kullanıcı mesajı, bot cevabı) alanlarını içerir.
    conn.commit() # Değişiklikleri kaydeder
    conn.close() # Veritabanı bağlantısını kapatır

# Veritabanlarını başlat
init_users_db()
for profession in DB_PATHS.keys():
    init_db(profession) 

def save_message(profession, session_id, role, message): # Veritabanına mesaj kaydetmek için
    db_path = DB_PATHS[profession] # İlgili professiona ait database git.
    conn = sqlite3.connect(db_path) # Veritabanına bağlan 
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç oluşturur
    c.execute("INSERT INTO chat_history (session_id, role, message) VALUES (?, ?, ?)",
              (session_id, role, message)) #İlgili database gittik, o databasenin chat_history tablosuna verileri insert eder.
    conn.commit() # Kaydeder.
    conn.close() # Kapatır.

def get_history_pairs(profession, session_id): # İlgili mesleğin veritabanından geçmiş mesajları alır, belirli session_id için user ve assistant mesajlarını çiftler halinde döndürür
    db_path = DB_PATHS[profession] # İlgili professiona ait veritabanına bağlan.
    conn = sqlite3.connect(db_path)
    c = conn.cursor() # SQL komutlarını çalıştırmak için bir imleç, cursor oluşturur
    c.execute("SELECT role, message FROM chat_history WHERE session_id = ? ORDER BY id ASC", (session_id,)) # chat_history tablosundan belirtilen session_id için role (user veya assistant) ve message (kullanıcı mesajı veya bot cevabı) alanlarını alır, id'ye göre artan sırada sıralar
    rows = c.fetchall() # Tüm satırları alır
    conn.close() # Kapatır.

    pairs = [] # Mesaj çiftlerini saklamak için boş bir liste oluşturur
    i = 0 # İndeks değişkeni, satırları döngüde gezmek için kullanılır
    while i < len(rows) - 1: # Satırların sonuna gelene kadar döngü devam eder
        if rows[i][0] == "user" and rows[i+1][0] == "assistant":  # Eğer şu anki satırın role'u "user" ve bir sonraki satırın role'u "assistant" ise
            pairs.append((rows[i][1], rows[i+1][1])) # Bu iki mesajı çift olarak listeye ekler
            i += 2 # İki satırı atlar, çünkü bir kullanıcı mesajı ve ona karşılık gelen bot cevabı zaten çift olarak eklendi
        else:
            i += 1 # Eğer şu anki satırın role'u "user" değilse veya bir sonraki satırın role'u "assistant" değilse, sadece bir satırı atlar
    return pairs # Mesaj çiftlerini döndürür




"""{ DECODED TOKEN:
  "user_id": "ab34-xyz-1234",
  "session_id": "uuid-789-sess-123",
  "exp": "..."
}"""

def get_user_from_token(): # Amacımız JWT üzerinden kullanıcı bilgilerini almak
    auth_header = request.headers.get("Authorization") # Authorization adlı header aldıkc
    if not auth_header or not auth_header.startswith("Bearer "): # doğru geldi mi gelmedi mi, bearer ile başlıyor mu başlamıyor mu
        return None
    token = auth_header.split(" ")[1] # Bearer token geldi, ayırdım, sadece token ı aldım
    try:
        decoded = jwt.decode(token, JWT_KEY, algorithms=[JWT_ALGORITHM]) # token ı JWT Key ile decode ettim.
        return {
            "user_id": decoded.get("user_id"),
            "username": decoded.get("username"),
            "profession": decoded.get("profession"),
            "session_id": decoded.get("session_id")
        }
    except jwt.ExpiredSignatureError: # JWT KEY in kullanma tarihi geçmiş mi
        return None
    except jwt.InvalidTokenError: # JWT Key doğru mu
        return None

def check_user_access(user_info, requested_profession): # Yetkisiz kullanıcıların başka mesleklerin endpointlerine erişimini engellemek için kullanılır.
    if not user_info: # user_info yoksa false dön
        return False
    return user_info["profession"] == requested_profession # Eğer user_infonun professionu ulaşılmak istenen professiona eşitse true dön

class ProfessionAgent: # Meslek bazlı agent sınıfı
    def __init__(self, profession_name, system_prompt, context_file):  # Agent'ın başlatılması için gerekli parametreler
        self.profession_name = profession_name # Meslek adı
        self.system_prompt = system_prompt # Sistem promptu, agent'ın nasıl davranması gerektiğini belirler
        self.context_file = context_file # Bağlam dosyası, agent'ın kullanacağı ek bilgi

    def get_context(self): # Bağlam bilgisini dosyadan al
        try:
            with open(self.context_file, 'r', encoding='utf-8') as f:# Bağlam dosyasını okur
                data = json.load(f)  # JSON formatındaki veriyi yükler
            
            lines = [] # Satırları saklamak için boş bir liste oluşturur
            for key, value in data.items(): # JSON verisindeki her anahtar-değer çifti için
                line = f"{key}: {value}" # Anahtar-değer çiftini "anahtar: değer" formatında bir satır olarak oluşturur
                lines.append(line) # Satırı listeye ekler
                result = "\n".join(lines) # Her anahtar-değer çiftini bir satır olarak birleştirir
            return result # Bağlam bilgisini döndürür
        
        except FileNotFoundError: # Eğer bağlam dosyası bulunamazsa
            return "No context data available."  # Hata mesajı döndürür, bağlam verisi yoksa

    def respond(self, user_message, history): # Geçmiş mesajları kullanarak kullacı mesajına cevap verir
        context = self.get_context() # Bağlam bilgisini alır
        messages = [{ #system rol ve context json dosyası verildi
            "role": "system",
            "content": f"{self.system_prompt}\n\nContext Information:\n{context}\n\n Please only use info from context, respond in the same language as the user's message."
        }]
        
        for user_msg, assistant_msg in history: # Geçmiş mesajları ekler
            messages.append({"role": "user", "content": user_msg}) # Geçmişteki kullanıcı mesajını ekler
            messages.append({"role": "assistant", "content": assistant_msg}) # Geçmişteki bot cevabını ekler
        messages.append({"role": "user", "content": user_message}) # Şu anki kullanıcı mesajını ekler

        response = client.chat.completions.create( # OpenAI API'sine istek gönderir
            model="gpt-4o",
            messages=messages,
            temperature=0.7
        )
        return response.choices[0].message.content.strip() # API'den gelen cevabı alır ve temizler, boşlukları kaldırır

# Her meslek için ayrı agent
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

# Login endpoint'i
@app.route("/login", methods=["POST"]) # Dikkat et, ASLA GET GÖNDERME
def login():
    data = request.get_json() # Kullanıcıdan gelen requesti json formatında al, data adında dictionary e kaydet
    username = data.get("username") # Dictionary den username bilgisini al
    password = data.get("password") # Girilen şifreyi al
    
    if not username or not password: # Eğer username veya password yoksa error ver
        return jsonify({"error": "Username and password are required"})
    
    conn = sqlite3.connect(USERS_DB) # Kullanıcı bilgilerini doğrulamak için database git
    c = conn.cursor() # İmleç oluştur
    c.execute("SELECT id, username, password_hash, profession FROM users WHERE username = ?", (username,)) # Girilen username ile eşleşen kaydı bul
    user = c.fetchone() # O satırı al
    conn.close() # Kapat
    
    if not user or not verify_password(password, user[2]): # Eğer kullanıcı bulunmadıysa veya Şifre hash karşılaştırmasından geçemediyse, yani şifre yanlışsa
        return jsonify({"error": "Invalid username or password"}),401 # Error ver
    
    # Token oluştur
    user_id = str(user[0]) # Veri tabanındaki User id si
    session_id = str(uuid.uuid4()) #Her login olduğunda unique session_id oluşturur.Bu sayede aynı kullanıcı farklı cihazlarda oturum açsa bile kullanabilir.
    profession = user[3] # Veri tabanındaki profession
    
    payload = { # Token içinde saklanacak bilgiler:
        "user_id": user_id,
        "username": username,
        "profession": profession,
        "session_id": session_id
    }
    token = jwt.encode(payload, JWT_KEY, algorithm=JWT_ALGORITHM) # Bu token kullanıcı oturumunu temsil eder ve backend’e her API çağrısında gereklidir.
    
    return jsonify({
        "token": token,
        "user_id": user_id,
        "username": username,
        "profession": profession,
        "session_id": session_id
    })

# Register endpoint'i
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()  # Kullanıcının girdiği verileri aldık
    username = data.get("username")
    password = data.get("password")
    profession = data.get("profession")
    
    if not username or not password or not profession: # Kontrol
        return jsonify({"error": "Username, password and profession are required"})
    
    if profession not in ["dentist", "hairdresser", "trainer"]: # Kontrol
        return jsonify({"error": "Invalid profession"})
    
    password_hash = hash_password(password) # Girilen şifreyi hashle
    
    try:
        conn = sqlite3.connect(USERS_DB) # User database kaydetmemiz lazım
        c = conn.cursor() # İmleç oluştur
        c.execute("INSERT INTO users (username, password_hash, profession) VALUES (?, ?, ?)",
                  (username, password_hash, profession)) # Kullanıcı verilerini ekle
        conn.commit() # Kaydet
        conn.close() # Kapat
        
        return jsonify({"message": "User registered successfully"})
    
    except sqlite3.IntegrityError: # Eğer zaten kayıtlı username varsa error ver
        return jsonify({"error": "Username already exists"}), 409

# Her meslek için ayrı endpoint (güvenlik kontrollü), hepsi handle_chat cağırıyor
@app.route("/dentist/chat", methods=["POST"])
def dentist_chat():
    return handle_chat("dentist")

@app.route("/hairdresser/chat", methods=["POST"])
def hairdresser_chat():
    return handle_chat("hairdresser")

@app.route("/trainer/chat", methods=["POST"])
def trainer_chat():
    return handle_chat("trainer")

def handle_chat(profession): #Amamcımız tek fonksiyonla tüm endpointlerin işini yapmak, ilgili professionu parametre olarak aldık.
    if request.method == "OPTIONS": # OPTIONS yaparsak, preflight, yani önce boş response oluşturup gerekli izinleri alıyoruz.
        response = app.make_response('')
        response.headers["Access-Control-Allow-Origin"] = "*" # Her yerden erişime izin ver
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization" # Header da Content Type ve Authorization olmasına izin ver
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS" # Bu http methodlarına izin ver
        response.headers["Access-Control-Allow-Credentials"] = "true" # Kimlik bilgileri, cookie için
        return response
    

    user_info = get_user_from_token() #Kullanıcı bilgilerini al
    if not user_info: 
        return jsonify({"error": "Unauthorized - Please login"})
    
    # Kullanıcının bu mesleğe erişim hakkı var mı kontrol et, sadece kendi mesleğinin olduğu endpointe gidebilsin.
    if not check_user_access(user_info, profession):
        return jsonify({"error": f"Access denied - You can only access {user_info['profession']} services"})
    
    data = request.get_json()
    user_message = data.get("message", "")
    
    if not user_message:
        return jsonify({"error": "Message is required"})

    lang = detect(user_message)
    history = get_history_pairs(profession, user_info["session_id"])
    
    if history:
        last_user_msg = history[-1][0]
        user_message = f"In continuation of: '{last_user_msg}'\n{user_message}"
    else:
        last_user_msg = ""

    agent = agents[profession]
    bot_reply = agent.respond(user_message, history)

    save_message(profession, user_info["session_id"], "user", user_message)
    save_message(profession, user_info["session_id"], "assistant", bot_reply)

    return jsonify({ 
        "response": bot_reply,
        "profession": profession,
        "language": lang,
        "username": user_info["username"]
    })

# Her meslek için ayrı history endpoint'i (güvenlik kontrollü)
@app.route("/dentist/history", methods=["GET"])
def dentist_history():
    return handle_history("dentist")

@app.route("/hairdresser/history", methods=["GET"])
def hairdresser_history():
    return handle_history("hairdresser")

@app.route("/trainer/history", methods=["GET"])
def trainer_history():
    return handle_history("trainer")

def handle_history(profession):
    """Her meslek için ortak history işlemi - güvenlik kontrollü"""
    user_info = get_user_from_token()

    if not user_info:
        return jsonify({"error": "Unauthorized - Please login"}), 401
    
    if not check_user_access(user_info, profession):
        return jsonify({"error": f"Access denied - You can only access {user_info['profession']} services"}), 403

    history = get_history_pairs(profession, user_info["session_id"])
    formatted = [{"user": user_msg, "assistant": assistant_msg} for user_msg, assistant_msg in history]
    return jsonify({"history": formatted})

# Kullanıcı profili endpoint'i
@app.route("/profile", methods=["GET"])
def get_profile():
    """Kullanıcı profilini getir"""
    user_info = get_user_from_token()
    if not user_info:
        return jsonify({"error": "Unauthorized - Please login"})
    
    return jsonify({
        "username": user_info["username"],
        "profession": user_info["profession"],
        "user_id": user_info["user_id"]
    })

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050) 
