import os
import shutil
from datetime import datetime
from app import app, db, Book  # assumes app.py in same folder

SRC_DIR = os.path.join(os.path.dirname(__file__), 'sample_pdfs')
DST_DIR = app.config['UPLOAD_FOLDER']

def seed():
    os.makedirs(SRC_DIR, exist_ok=True)
    os.makedirs(DST_DIR, exist_ok=True)
    files = [f for f in os.listdir(SRC_DIR) if f.lower().endswith('.pdf')]
    if not files:
        print('No PDF files found in sample_pdfs/. Place some PDFs there and re-run.')
        return

    for f in files:
        src = os.path.join(SRC_DIR, f)
        filename = f"{int(datetime.utcnow().timestamp())}_{f}"
        dst = os.path.join(DST_DIR, filename)
        shutil.copy2(src, dst)
        # For title/author/year - we derive from filename as a simple heuristic
        title = os.path.splitext(f)[0].replace('_',' ').title()
        author = 'Unknown'
        year = ''
        book = Book(title=title, author=author, year=year, filename=filename)
        db.session.add(book)
    db.session.commit()
    print(f'Added {len(files)} books to the DB.')

if __name__ == '__main__':
    with app.app_context():
        seed()
