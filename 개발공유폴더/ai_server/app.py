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
import io
import hashlib
import pyodbc
import numpy as np
import os

def process_result_and_store(df):

    # 2. 컬럼 순서 재정렬
    desired_order = [
        'Name', 'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp',
        'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'Machine',
        'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
        'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
        'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment', 'FileAlignment',
        'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
        'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum', 'SizeOfImage', 'Subsystem',
        'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
        'LoaderFlags', 'NumberOfRvaAndSizes', 'Malware',  # <- Malware 컬럼 추가
        'SuspiciousImportFunctions', 'SuspiciousNameSection', 'SectionsLength', 'SectionMinEntropy', 'SectionMaxEntropy',
        'SectionMinRawsize', 'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize', 'SectionMaxPhysical',
        'SectionMinPhysical', 'SectionMaxVirtual', 'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData',
        'SectionMaxChar', 'SectionMainChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize', 'DirectoryEntryExport',
        'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport', 'ImageDirectoryEntryResource', 'ImageDirectoryEntryException',
        'ImageDirectoryEntrySecurity'
    ]
    
    # 데이터프레임에 존재하는 컬럼만 추출
    existing_columns = df.columns.tolist()
    desired_columns = [col for col in desired_order if col in existing_columns]

    df = df[desired_columns]  # 재정렬 적용
    df = df.fillna(0)  # None을 0으로 대체

    # DB 저장
    for _, row in df.iterrows():
        row_values = [str(value) for value in row.values]
        row_str = ','.join(row_values)
        row_hash = hashlib.sha256(row_str.encode('utf-8')).hexdigest()

        conn = pyodbc.connect(
            r"Driver={ODBC Driver 18 for SQL Server};"
            r"Server=DESKTOP-LGI1JDQ\SQLEXPRESS;"
            r"Database=test;"
            r"UID=sa;"
            r"PWD=root;"
            r"TrustServerCertificate=yes;"
        )
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM HE WHERE CAST(HashName AS VARCHAR(255)) = ?", (row_hash,))
        exists = cursor.fetchone()[0]

        if exists == 0:
            cursor.execute("INSERT INTO HE (HashName) VALUES (?)", (row_hash,))

            insert_query = f"""
                INSERT INTO [dbo].[TE] (
                    {', '.join(desired_columns)}
                ) VALUES ({', '.join(['?'] * len(desired_columns))});
            """
            cursor.execute(insert_query, tuple(row_values))  # 모든 값을 문자열로 변환하여 삽입

        conn.commit()
        cursor.close()
        conn.close()




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

        file_test = []

        file_test.append(io.BytesIO(file_bytes))

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

        r_test = clc.avg()


####################

        # 첫 번째 행 제외하고 0.5 이하 비교
        rest = (r_test['0'] <= 0.5).astype(int).tolist()


        #print("매우중요", rest)

        # file_test[0]은 네가 업로드한 파일 내용 (bytes 형태)
        csv_text = file_test[0].getvalue().decode('utf-8')
        #print("매우매우", csv_text)

        # 먼저 데이터 읽어오기
        df = pd.read_csv(io.StringIO(csv_text))

        # 'Malware' 컬럼 추가
        df['Malware'] = rest

        # 네가 지정한 열 순서
        column_order = [
            'Name', 'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',
            'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_oemid', 'e_oeminfo',
            'e_lfanew', 'Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable',
            'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics', 'Magic',
            'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
            'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase',
            'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
            'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
            'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum',
            'SizeOfImage', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
            'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags',
            'NumberOfRvaAndSizes', 'Malware', 'SuspiciousImportFunctions', 'SuspiciousNameSection',
            'SectionsLength', 'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMinRawsize',
            'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize',
            'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual', 'SectionMinVirtual',
            'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar', 'SectionMainChar',
            'DirectoryEntryImport', 'DirectoryEntryImportSize', 'DirectoryEntryExport',
            'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport', 'ImageDirectoryEntryResource',
            'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity'
        ]

        df['Name'] = df['Name'].apply(lambda x: os.path.basename(x))

        # 컬럼 순서 맞추기
        df = df[column_order]


        print("중요한 값들 : ",df)

#######
        process_result_and_store(df)
#######

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