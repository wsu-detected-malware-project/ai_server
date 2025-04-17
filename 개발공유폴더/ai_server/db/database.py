import pyodbc

# DB 연결 함수
def connect_db():
    connection = pyodbc.connect(
        r"Driver={ODBC Driver 18 for SQL Server};"
        r"Server=DESKTOP-LGI1JDQ\SQLEXPRESS;"
        r"Database=test;"
        r"UID=sa;"
        r"PWD=root;"
        r"TrustServerCertificate=yes;"
    )
    print("SQL Server 데이터베이스에 연결되었습니다.")
    return connection