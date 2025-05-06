import hashlib
import pandas as pd
import io
import os

from db.db_columns import column_order
from sqlalchemy import text

def result_db_upload(df, db_connection):
    existing_columns = df.columns.tolist()
    desired_columns = [col for col in column_order if col in existing_columns]

    df = df[column_order]
    df = df.fillna(0)

    for _, row in df.iterrows():
        # 필요한 컬럼만 추출 + 문자열 변환
        row_dict = {col: str(row[col]) for col in desired_columns}
        row_str = ','.join(row_dict.values())
        row_hash = hashlib.sha256(row_str.encode('utf-8')).hexdigest()

        # 해시 중복 체크
        result = db_connection.execute(
            text("SELECT COUNT(*) FROM HAA WHERE CAST(HashName AS VARCHAR(255)) = :hashname"),
            {"hashname": row_hash}
        )
        exists = result.scalar()

        if exists == 0:
            # 해시 저장
            db_connection.execute(
                text("INSERT INTO HAA (HashName) VALUES (:hashname)"),
                {"hashname": row_hash}
            )

            # TEE 삽입 쿼리 준비
            insert_query = text(f"""
                INSERT INTO [dbo].[TEE] (
                    {', '.join(desired_columns)}
                ) VALUES (
                    {', '.join([f':{col}' for col in desired_columns])}
                )
            """)

            # dict 형식으로 안전하게 넘김
            db_connection.execute(insert_query, row_dict)

    db_connection.commit()


def update_file(sum_of_values, client_pe_file):
    # 첫 번째 행 제외하고 0.5 이하 비교
    malware_of_values = (sum_of_values['0'] <= 0.5).astype(int).tolist()

    # 파일 내용 읽기
    csv_text = client_pe_file[0].getvalue().decode('utf-8')
    df = pd.read_csv(io.StringIO(csv_text))

    # 'Malware' 컬럼 추가
    df['Malware'] = malware_of_values
    df['Name'] = df['Name'].apply(lambda x: os.path.basename(x))

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
    return "SELECT * FROM [dbo].[TEE];"
