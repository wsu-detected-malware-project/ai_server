import pyodbc

# DB 연결 함수
def db_connect():
    try:
        connection = pyodbc.connect(
            r"Driver={ODBC Driver 18 for SQL Server};"
            r"Server=DESKTOP-LGI1JDQ\SQLEXPRESS;"
            r"Database=test;"
            r"UID=sa;"
            r"PWD=root;"
            r"TrustServerCertificate=yes;"
        )
        return connection
    except pyodbc.Error as e:
        print("DB 연결 실패:", e)
        return None