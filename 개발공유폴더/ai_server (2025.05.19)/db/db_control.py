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

            # Malware 값에 따라 테이블 결정
            malware_type = int(row['Malware'])
            if malware_type in [0, 1]:
                table_name = 'TEE'
            elif malware_type == 2:
                table_name = 'IFF'
            else:
                continue  # 예외 값 무시

            # 삽입 쿼리 준비
            insert_query = text(f"""
                INSERT INTO [dbo].[{table_name}] (
                    {', '.join(desired_columns)}
                ) VALUES (
                    {', '.join([f':{col}' for col in desired_columns])}
                )
            """)

            # dict 형식으로 안전하게 넘김
            db_connection.execute(insert_query, row_dict)

    db_connection.commit()


def update_file(sum_of_values, client_pe_file):
    #비교해서 0, 1, 2 넣는 코드 2 
    malware_of_values = sum_of_values['0'].apply(
        lambda x: 0 if x >= 0.7 else (2 if (x >= 0.5 and x < 0.7) else 1)
    ).tolist()

    # 1. BytesIO에서 원본 CSV 문자열 읽기
    original_csv_text = client_pe_file[0].getvalue().decode('utf-8')

    # 2. 문자열을 DataFrame으로 변환 후 중복 제거
    temp_df = pd.read_csv(io.StringIO(original_csv_text))
    temp_df = temp_df.drop_duplicates(subset='Name')

    # 3. 중복 제거된 내용을 다시 CSV 문자열로 변환
    csv_text = temp_df.to_csv(index=False)

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
