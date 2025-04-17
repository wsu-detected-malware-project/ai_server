import numpy as np
import pandas as pd
from xgboost import XGBClassifier  
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_curve, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import os
import warnings
warnings.simplefilter('ignore')
import mysql.connector
import pyodbc
import csv
from sklearn.preprocessing import LabelEncoder  # 추가

def xgboost(file):
    #df = pd.read_csv('./dataset/dataset_malwares.csv')
    #df = pd.read_csv('C:/Users/pth81/Desktop/ai_server/dataset/dataset_malwares.csv')
    df1 = pd.read_csv(file)

    # SQL Server에 연결 (TrustServerCertificate=yes 추가)

    db_connection = pyodbc.connect(
        r"Driver={ODBC Driver 18 for SQL Server};"  # 드라이버 이름
        r"Server=DESKTOP-LGI1JDQ\SQLEXPRESS;"  # 서버 이름
        r"Database=test;"                      # 사용할 데이터베이스
        r"UID=sa;"                             # 사용자 이름
        r"PWD=root;"                           # 비밀번호
        r"TrustServerCertificate=yes;"         # SSL 인증서 문제 무시
    )

    # 연결 성공 확인
    print("SQL Server 데이터베이스에 연결되었습니다.")

    # SQL 쿼리 실행하여 TE 테이블의 데이터를 DataFrame에 저장
    query = "SELECT * FROM [dbo].[TE];"
    df = pd.read_sql(query, db_connection)

    # 이제 df에는 TE 테이블의 모든 데이터가 들어가 있습니다

    # 연결 종료
    db_connection.close()



    dropped_df = df.drop(['Name','Malware'],axis=1)

    x = dropped_df
    y = df['Malware']
##############################
    # y를 LabelEncoder로 숫자형으로 변환
    label_encoder = LabelEncoder()  # **추가된 부분**
    y = label_encoder.fit_transform(y)  # ['0', '1'] -> [0, 1]로 변환
##############################

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_train)
    x_new = pd.DataFrame(x_scaled, columns=x.columns)

    skpca = PCA(n_components=55)
    x_pca = skpca.fit_transform(x_new)

    model = XGBClassifier(
        n_estimators=100,          
        random_state=42,           
        max_depth=16,              
        objective='binary:logistic', 
        eval_metric='logloss'   
    )

    model.fit(x_pca, y_train)

    x_test_scaled = scaler.transform(x_test)
    x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
    x_test_pca = skpca.transform(x_new_test)

    y_pred = model.predict(x_test_pca)

    print('--------------------------xgboost----------------------------------')
    print(classification_report(y_pred, y_test))

    pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])
    x_testing = df1.drop('Name', axis=1)

    x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
    x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
    y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)

    result = pd.concat([df1['Name'], pd.DataFrame(y_testing_pred)], axis=1)
    print(result)
    result.to_csv('ai4_result.csv', index=False)

    return result
