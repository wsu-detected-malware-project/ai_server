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
import threading

from db.db_login import db_connect
from db.db_control import background_work

app = Flask(__name__)

@app.route('/upload', methods = ['POST'])
def upload_file():

    if 'file' not in request.files:
        return '전송된 파일 없음', 400
    
    file = request.files['file']

    if file.filename == '':
        return '선택 된 파일 없음', 400
    
    print('받기 성공')
   
    try:
        # DB 연결
        db_connection = db_connect()

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

        output = io.StringIO()
        result.to_csv(output, index=False)
        output.seek(0)
        
        # ====== update_file + result_db_upload 비동기로 실행 ======
        thread = threading.Thread(target=background_work, args=(sum_of_values, client_pe_file, db_connection))
        thread.start()

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