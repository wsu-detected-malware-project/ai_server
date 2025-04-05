import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import os
import warnings
warnings.simplefilter('ignore')

# 데이터 불러오기
df = pd.read_csv('./dataset_malwares.csv')
df1 = pd.read_csv('./dataset_test.csv')

# 라벨 및 피처 준비
x = df.drop(['Name','Malware'], axis=1)
y = df['Malware']

# 학습/테스트 분할
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

# 스케일링
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x_train)
x_new = pd.DataFrame(x_scaled, columns=x.columns)

# PCA 적용
skpca = PCA(n_components=55)
x_pca = skpca.fit_transform(x_new)
print('Variance sum :', skpca.explained_variance_.cumsum()[-1])

# 모델: LightGBM
model = LGBMClassifier(
    n_estimators=100,
    random_state=0,
    max_depth=16,
    n_jobs=-1,
    verbose=-1
)

# 모델 학습
model.fit(x_pca, y_train)

# 테스트 데이터 처리
x_test_scaled = scaler.transform(x_test)
x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
x_test_pca = skpca.transform(x_new_test)

# 예측
y_pred = model.predict(x_test_pca)
print(classification_report(y_pred, y_test))

# 예측 파이프라인
pipe = Pipeline([
    ('scale', scaler),
    ('pca', skpca),
    ('clf', model)
])

# 테스트 데이터셋 적용 (예측 확률 출력)
x_testing = df1.drop('Name', axis=1)
x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)

# 결과 저장
results = pd.concat([
    df1['Name'],
    pd.DataFrame(y_testing_pred, columns=['Not Malware', 'Malware'])
], axis=1)

results.to_csv('malware_files.csv', index=False)
print("✅ 예측 결과가 'malware_predictions.csv'에 저장되었습니다.")
