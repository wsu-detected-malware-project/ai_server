from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# DB 연결 정보
DATABASE_URL = (
    "mssql+pyodbc://sa:root@DESKTOP-LGI1JDQ\\SQLEXPRESS/Malware_Dataset"
    "?driver=ODBC+Driver+18+for+SQL+Server"
    "&TrustServerCertificate=yes"
)

# SQLAlchemy 엔진 생성
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

# 세션 클래스 생성
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 세션 가져오는 함수
def db_connect():
    return SessionLocal()
