from flask import Flask, request, send_file
from db.db_login import db_connect
import io
import ai_model.lgvm as ai1
import ai_model.random_forest as ai2
import ai_model.svm as ai3
import ai_model.xgboost as ai4
import db.db_control as db
import calculate.avg as clc
import calculate.dis as dis
import traceback
import threading

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

        if db_connection is not None:
            print("SQL Server 데이터베이스에 연결되었습니다.")
        else:
            raise Exception("DB 연결에 실패했습니다.")
           
        #file 값 담기
        file_bytes = file.read()
        file_content = []
        client_pe_file = []

        client_pe_file.append(io.BytesIO(file_bytes))

        for i in range(4):
            file_content.append(io.BytesIO(file_bytes))

        # --- 비동기로 실행할 함수들 정의 ---
        thread_lgvm = threading.Thread(target=ai1.lgvm, args=(file_content[0],))
        thread_rf = threading.Thread(target=ai2.rd_forest, args=(file_content[1],))
        thread_svm = threading.Thread(target=ai3.svm, args=(file_content[2],))
        thread_xgb = threading.Thread(target=ai4.xgboost, args=(file_content[3],))

        # --- 스레드 시작 ---
        thread_lgvm.start()
        thread_rf.start()
        thread_svm.start()
        thread_xgb.start()

        # --- 모든 스레드가 끝날 때까지 대기 ---
        thread_lgvm.join()
        thread_rf.join()
        thread_svm.join()
        thread_xgb.join()

        #합산
        sum_of_values = clc.avg()

        #결과
        result = dis.dis()

        output = io.StringIO()
        result.to_csv(output, index=False)
        output.seek(0)
        
        # ====== update_file + result_db_upload 비동기로 실행 ======
        thread = threading.Thread(target=db.background_work, args=(sum_of_values, client_pe_file, db_connection))
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
    app.run(host='0.0.0.0',port=8080, debug=False)