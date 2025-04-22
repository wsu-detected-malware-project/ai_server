import hashlib
import pandas as pd
import io
import os

from colums.db_columns import column_order

def result_db_upload(df, db_connection):

    # 데이터프레임에 존재하는 컬럼만 추출
    existing_columns = df.columns.tolist()
    desired_columns = [col for col in column_order if col in existing_columns]

    df = df[column_order]  # 재정렬 적용
    df = df.fillna(0)  # None을 0으로 대체

    # DB 저장
    for _, row in df.iterrows():
        row_values = [str(value) for value in row.values]
        row_str = ','.join(row_values)
        row_hash = hashlib.sha256(row_str.encode('utf-8')).hexdigest()

        cursor = db_connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM HA WHERE CAST(HashName AS VARCHAR(255)) = ?", (row_hash,))
        exists = cursor.fetchone()[0]

        if exists == 0:
            cursor.execute("INSERT INTO HA (HashName) VALUES (?)", (row_hash,))

            insert_query = f"""
                INSERT INTO [dbo].[TE] (
                    {', '.join(desired_columns)}
                ) VALUES ({', '.join(['?'] * len(desired_columns))});
            """
            cursor.execute(insert_query, tuple(row_values))  # 모든 값을 문자열로 변환하여 삽입

        db_connection.commit()
        cursor.close()

def update_file(sum_of_values, client_pe_file):
    # 첫 번째 행 제외하고 0.5 이하 비교
    malware_of_values = (sum_of_values['0'] <= 0.5).astype(int).tolist()

    # client_pe_file[0]은 네가 업로드한 파일 내용 (bytes 형태)
    csv_text = client_pe_file[0].getvalue().decode('utf-8')

    # 먼저 데이터 읽어오기
    df = pd.read_csv(io.StringIO(csv_text))

    # 'Malware' 컬럼 추가
    df['Malware'] = malware_of_values

    df['Name'] = df['Name'].apply(lambda x: os.path.basename(x))

    # 컬럼 순서 맞추기
    df = df[column_order]

    return df

def background_work(sum_of_values, client_pe_file, db_connection):
    try:
        df = update_file(sum_of_values, client_pe_file)
        result_db_upload(df, db_connection)
    except Exception as e:
        print('Background 작업 중 에러:', e)
    finally:
        print("db 닫힘")
        db_connection.close()

def search():
    return "SELECT * FROM [dbo].[TE];"