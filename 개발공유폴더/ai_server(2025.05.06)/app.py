import os
import subprocess
import threading
from auto_update import run_scheduler
from flask import Flask, request, send_file
from db.db_login import db_connect, engine
import io
import ai_model.lgvm as ai1
import ai_model.random_forest as ai2
import ai_model.svm as ai3
import ai_model.xgboost as ai4
import db.db_control as db
import calculate.avg as clc
import calculate.t_stamp as timestamp
import calculate.dis as dis
import traceback
import threading

app = Flask(__name__)

MODEL_PATHS = [
    './models/random_forest_model.pkl',
    './models/lgvm_model.pkl',
    './models/svm_model.pkl',
    './models/xgboost_model.pkl'
]

@app.route('/upload', methods = ['POST'])
def upload_file():

    if 'file' not in request.files:
        print('전송 된 파일 없음')
        return '전송된 파일 없음', 400
    
    file = request.files['file']

    if file.filename == '':
        print('선택 된 파일 없음')
        return '선택 된 파일 없음', 400
    
    print(f'{file} 받기 성공')

    try:
        #file 들어온 시간 기준
        time = timestamp.timestampe()

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

        #AI 모델
        threads = [
            threading.Thread(target=ai1.lgvm, args=(file_content[0],time, engine)),
            threading.Thread(target=ai2.rd_forest, args=(file_content[1],time, engine)),
            threading.Thread(target=ai3.svm, args=(file_content[2],time, engine)),
            threading.Thread(target=ai4.xgboost, args=(file_content[3],time, engine)),
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        #합산
        sum_of_values = clc.avg(time)

        #결과
        result = dis.dis(time)

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

# 백그라운드에서 모델 자동 재학습 스레드 시작
def start_background_trainer():
    thread = threading.Thread(target=run_scheduler, daemon=True)
    thread.start()
    
#처음 프로그램 실행시 trainer.py 작동
def ensure_models_exist():
    if not all(os.path.exists(path) for path in MODEL_PATHS):
        print("모델 파일이 누락되어 있어 trainer.py를 실행합니다.")
        subprocess.run(['python', 'trainer.py'])
    else:
        print("모든 모델이 존재합니다. 학습을 건너뜁니다.")
    
if __name__ == '__main__':
    ensure_models_exist()
    start_background_trainer()
    app.run(host='0.0.0.0',port=8080, debug=False)