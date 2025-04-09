from flask import Flask, request, send_file
import io
import ai_model.lgvm as ai1
import ai_model.random_forest as ai2
import ai_model.svm as ai3
import ai_model.xgboost as ai4
import calculate.avg as clc
import calculate.dis as dis
import traceback

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

        #file 값 담기
        file_bytes = file.read()
        file_content = []
        for i in range(4):
            file_content.append(io.BytesIO(file_bytes))

        #AI 모델
        ai1.lgvm(file_content[0])
        ai2.rd_forest(file_content[1])
        ai3.svm(file_content[2])
        ai4.xgboost(file_content[3])

        #합산
        clc.avg()

        #결과
        result = dis.dis()

        output = io.StringIO()
        result.to_csv(output, index=False)
        output.seek(0)

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