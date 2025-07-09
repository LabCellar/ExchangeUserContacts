import sys
import re
import time
import mysql.connector
from mysql.connector import errorcode
from exchangelib import Credentials, Account, Configuration, IMPERSONATION
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib.errors import ErrorNonExistentMailbox
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from datetime import datetime

import ssl

# CONFIGURATION: EDIT THESE FOR YOUR ENVIRONMENT
EWS_URL = 'https://your.exchange.server/EWS/Exchange.asmx'
ADMIN_EMAIL = 'admin@yourdomain.com'
ADMIN_PASS = 'YOUR_ADMIN_PASSWORD'

DB_HOST = 'localhost'
DB_NAME = 'exchange_contacts'
DB_USER = 'exchangeuser'
DB_PASS = 'exchangepass'

# Active Directory configuration
AD_SERVER = 'ad.yourdomain.com'
AD_USER = 'YOURDOMAIN\\Administrator'  # DOMAIN\\user format
AD_PASS = 'YOUR_AD_PASSWORD'
AD_SEARCH_BASE = 'DC=yourdomain,DC=com'  # Change to your AD root

# Disable SSL verification (for self-signed Exchange)
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
ssl._create_default_https_context = ssl._create_unverified_context

def log_execution(cursor, subfunction_name, status, message=None, exchange_count=None, inserted_count=None):
    """
    Logs the execution of a subfunction.
    Keeps only the 1000 last logs.
    If exchange_count or inserted_count are set, saves them in the log.
    """
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    sql = "INSERT INTO logs (timestamp, subfunction, status, message, exchange_count, inserted_count) VALUES (%s, %s, %s, %s, %s, %s)"
    cursor.execute(sql, (now, subfunction_name, status, message, exchange_count, inserted_count))
    # Delete oldest logs to keep only 1000 entries
    cursor.execute("""
        DELETE FROM logs
        WHERE id NOT IN (
            SELECT id FROM (
                SELECT id FROM logs ORDER BY id DESC LIMIT 1000
            ) AS last_logs
        )
    """)

def ensure_database_and_tables():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        conn.database = DB_NAME
        # Main table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                user_phone VARCHAR(100),
                contact_name VARCHAR(255) NOT NULL,
                contact_email VARCHAR(255),
                contact_phone VARCHAR(100),
                contact_company VARCHAR(255)
            ) CHARACTER SET=utf8mb4;
        """)
        # Processing table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                user_phone VARCHAR(100),
                contact_name VARCHAR(255) NOT NULL,
                contact_email VARCHAR(255),
                contact_phone VARCHAR(100),
                contact_company VARCHAR(255)
            ) CHARACTER SET=utf8mb4;
        """)
        # Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                subfunction VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                message TEXT,
                exchange_count INT,
                inserted_count INT
            ) CHARACTER SET=utf8mb4;
        """)
        cursor.close()
        conn.close()
        print("Database and tables ready.")
    except mysql.connector.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit(1)

def clear_table(cursor, table_name):
    try:
        cursor.execute(f"TRUNCATE TABLE {table_name};")
        print(f"{table_name.capitalize()} table cleared.")
        log_execution(cursor, f"clear_table:{table_name}", "success", "Table cleared.")
    except mysql.connector.Error as err:
        log_execution(cursor, f"clear_table:{table_name}", "error", str(err))
        print(f"Error clearing {table_name} table: {err}")
        sys.exit(1)

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            charset='utf8mb4'
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        sys.exit(1)

def insert_processing(cursor, user_email, user_phone, contact_name, contact_email, contact_phone, contact_company):
    sql = """
    INSERT INTO processing
    (user_email, user_phone, contact_name, contact_email, contact_phone, contact_company)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(sql, (user_email, user_phone, contact_name, contact_email, contact_phone, contact_company))

def format_e164(phone):
    """
    Converts a phone number to +E.164 format, removing spaces and formatting.
    Handles French national format as well.
    Returns None if the number cannot be reformatted to E.164.
    """
    if not phone:
        return None

    # Remove spaces, hyphens, parentheses, dots
    phone = re.sub(r"[ \-\(\)\.]", "", phone)

    # Accept leading '+'
    if phone.startswith("+"):
        if re.match(r"^\+\d{8,15}$", phone):
            return phone
        else:
            return None

    # Accept leading '00' international format
    if phone.startswith("00"):
        phone = "+" + phone[2:]
        if re.match(r"^\+\d{8,15}$", phone):
            return phone
        else:
            return None

    # French national format: 0 followed by 9 digits (total 10 digits)
    if re.match(r"^0\d{9}$", phone):
        # Remove leading 0, add +33
        return "+33" + phone[1:]

    return None  # Not a valid E.164 or supported national format

def fetch_mail_enabled_users_from_ad(cursor):
    subfn = "fetch_mail_enabled_users_from_ad"
    try:
        print("Retrieving mail-enabled users from Active Directory...")
        server = Server(AD_SERVER, get_info=ALL)
        conn = Connection(server, user=AD_USER, password=AD_PASS, authentication=NTLM, auto_bind=True)
        ad_filter = '(&(objectClass=user)(mail=*)(msExchRecipientTypeDetails:1.2.840.113556.1.4.803:=1))'
        conn.search(
            search_base=AD_SEARCH_BASE,
            search_filter=ad_filter,
            search_scope=SUBTREE,
            attributes=['mail', 'proxyAddresses', 'telephoneNumber']
        )
        user_infos = []
        for entry in conn.entries:
            primary_smtp = None
            proxy_addresses = entry.proxyAddresses.values if 'proxyAddresses' in entry and entry.proxyAddresses else []
            for addr in proxy_addresses:
                if addr.startswith('SMTP:'):
                    primary_smtp = addr[5:]
                    break
            if not primary_smtp and 'mail' in entry and entry.mail:
                primary_smtp = str(entry.mail)
            if primary_smtp:
                raw_phone = str(entry.telephoneNumber) if 'telephoneNumber' in entry and entry.telephoneNumber else None
                user_phone = format_e164(raw_phone) if raw_phone else None
                user_infos.append({'email': primary_smtp, 'phone': user_phone})
        log_execution(cursor, subfn, "success", f"Found {len(user_infos)} mail-enabled users")
        print(f"Found {len(user_infos)} mail-enabled users in AD (primary SMTP addresses).")
        return user_infos
    except Exception as err:
        log_execution(cursor, subfn, "error", str(err))
        print(f"Active Directory user discovery failed: {err}")
        sys.exit(1)

def replace_contacts_with_processing(cursor, db):
    subfn = "replace_contacts_with_processing"
    try:
        clear_table(cursor, "contacts")
        cursor.execute("""
            INSERT INTO contacts (user_email, user_phone, contact_name, contact_email, contact_phone, contact_company)
            SELECT user_email, user_phone, contact_name, contact_email, contact_phone, contact_company FROM processing
        """)
        db.commit()
        log_execution(cursor, subfn, "success", "contacts table replaced with processing table content")
        print("contacts table replaced with processing table content.")
    except mysql.connector.Error as err:
        log_execution(cursor, subfn, "error", str(err))
        print(f"Error replacing contacts table: {err}")
        sys.exit(1)

def process_user_contacts(cursor, db, user_email, user_phone, config):
    """
    Process contacts for a single Exchange user, insert into processing,
    and return (total_in_exchange, successfully_imported) for logging.
    """
    imported_count = 0
    total_count = 0
    try:
        print(f"Processing contacts for {user_email}...")
        account = Account(
            primary_smtp_address=user_email,
            config=config,
            autodiscover=False,
            access_type=IMPERSONATION
        )
        contacts = list(account.contacts.all())
        total_count = len(contacts)
        for contact in contacts:
            contact_name = contact.display_name or ''
            # Get first email address (can be multiple)
            contact_email = ''
            if contact.email_addresses:
                for e in contact.email_addresses:
                    if hasattr(e, 'email') and e.email:
                        contact_email = str(e.email)
                        break
            contact_phone = ''
            if contact.phone_numbers:
                for p in contact.phone_numbers:
                    if hasattr(p, 'phone_number') and p.phone_number:
                        contact_phone = format_e164(str(p.phone_number))
                        if contact_phone:
                            break
            contact_company = contact.company_name or ''
            try:
                insert_processing(cursor,
                    user_email,
                    user_phone,
                    contact_name,
                    contact_email,
                    contact_phone,
                    contact_company
                )
                imported_count += 1
            except Exception:
                pass
        db.commit()
        print(f"Done with {user_email}.")
        return total_count, imported_count
    except ErrorNonExistentMailbox:
        log_execution(cursor, "process_user_contacts", "error", f"Mailbox not found: {user_email}")
        print(f"Mailbox not found: {user_email}. Skipping.")
        return 0, 0
    except Exception as e:
        log_execution(cursor, "process_user_contacts", "error", f"Error processing {user_email}: {e}")
        print(f"Error processing {user_email}: {e}")
        return 0, 0

def main():
    # Start time for duration calculation
    start_time = time.perf_counter()

    # Step 1: Ensure DB and Tables exist
    ensure_database_and_tables()
    db = get_db_connection()
    cursor = db.cursor()

    # BEGINNING OF PROCESSING log entry
    log_execution(cursor, "BEGINNING OF PROCESSING", "info", "Processing started.")

    # Step 2: Clear processing table before processing
    clear_table(cursor, "processing")
    db.commit()

    # Step 3: EWS config
    credentials = Credentials(username=ADMIN_EMAIL, password=ADMIN_PASS)
    config = Configuration(service_endpoint=EWS_URL, credentials=credentials)

    # Step 4: Fetch mail-enabled users' primary SMTP addresses and phone from AD
    user_infos = fetch_mail_enabled_users_from_ad(cursor)

    # For total summary
    total_exchange_contacts = 0
    total_successful_inserts = 0

    for user in user_infos:
        user_email = user['email']
        user_phone = user['phone']
        total_contacts = 0
        imported_contacts = 0
        try:
            total_contacts, imported_contacts = process_user_contacts(cursor, db, user_email, user_phone, config)
            total_exchange_contacts += total_contacts
            total_successful_inserts += imported_contacts
            log_execution(
                cursor,
                "process_user_contacts_summary",
                "success",
                f"{user_email}",
                exchange_count=total_contacts,
                inserted_count=imported_contacts
            )
        except Exception as e:
            log_execution(cursor, "process_user_contacts_summary", "error", f"{user_email}: {e}")

    # Step 5: Total summary row
    log_execution(
        cursor,
        "total_contacts_summary",
        "success",
        "Total contacts processed and imported",
        exchange_count=total_exchange_contacts,
        inserted_count=total_successful_inserts
    )

    # Step 6: Replace contacts table with processing table content
    replace_contacts_with_processing(cursor, db)

    # END OF PROCESSING log entry with duration in seconds
    end_time = time.perf_counter()
    total_duration = end_time - start_time
    log_execution(
        cursor,
        "END OF PROCESSING",
        "info",
        f"PROCESSING ENDED. TOTAL DURATION: {total_duration:.2f} seconds."
    )
    db.commit()  # Ensure the last log is saved

    cursor.close()
    db.close()
    print("All done.")

if __name__ == '__main__':
    main()
