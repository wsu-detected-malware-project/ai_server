from flask import Flask, request, send_file
import io
import ai_model.lgvm as ai1
import ai_model.random_forest as ai2
import ai_model.svm as ai3
import ai_model.xgboost as ai4
import calculate.avg as clc
import calculate.dis as dis
import traceback
import hashlib
import pyodbc
import pandas as pd
import os

from db.database import connect_db
from col.columns import column_order

def process_result_and_store(df, db_connection):

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



app = Flask(__name__)

@app.route('/upload', methods = ['POST'])
def upload_file():

    if 'file' not in request.files:
        return '전송된 파일 없음', 400
    
    file = request.files['file']

    if file.filename == '':
        return '선택 된 파일 없음', 400
    
    print('받기 성공')
   
    # DB 연결
    db_connection = connect_db()

    try:

        #file 값 담기
        file_bytes = file.read()
        file_content = []
        client_pe_file = []

        client_pe_file.append(io.BytesIO(file_bytes))

        for i in range(4):
            file_content.append(io.BytesIO(file_bytes))

        #AI 모델
        ai1.lgvm(file_content[0], db_connection)
        ai2.rd_forest(file_content[1], db_connection)
        ai3.svm(file_content[2], db_connection)
        ai4.xgboost(file_content[3], db_connection)

        #합산
        sum_of_values = clc.avg()

        #결과
        result = dis.dis()

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

        #DB에 값 비교해서 넣는 코드
        process_result_and_store(df, db_connection)

        output = io.StringIO()
        result.to_csv(output, index=False)
        output.seek(0)

        # 연결 종료
        db_connection.close()

        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='result.csv'
        )

    except Exception as e:
        traceback.print_exc()
        return f"서버에서 오류 발생: {str(e)}", 500   
    
if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8080, debug=False)