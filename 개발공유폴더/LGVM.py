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

# 데이터 로드
df = pd.read_csv('./dataset_malwares.csv')
df1 = pd.read_csv('./dataset_test.csv')

# 불필요한 열 제거
dropped_df = df.drop(['Name','Malware'], axis=1)

# 특성 목록 (사용은 하지 않지만 유지)
features = ['e_magic','e_cblp','e_cp','e_crlc','e_cparhdr','e_minalloc','e_maxalloc','e_ss','e_sp','e_csum','e_ip','e_cs','e_lfarlc','e_ovno','e_oemid','e_oeminfo',
            'e_lfanew','Machine','NumberOfSections','TimeDateStamp','PointerToSymbolTable','NumberOfSymbols','SizeOfOptionalHeader','Characteristics',
            'Magic','MajorLinkerVersion','MinorLinkerVersion','SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData','AddressOfEntryPoint',
            'BaseOfCode','ImageBase','SectionAlignment','FileAlignment','MajorOperatingSystemVersion','MinorOperatingSystemVersion','MajorImageVersion',
            'MinorImageVersion','MajorSubsystemVersion','MinorSubsystemVersion','SizeOfHeaders','CheckSum','SizeOfImage','Subsystem','DllCharacteristics',
            'SizeOfStackReserve','SizeOfStackCommit','SizeOfHeapReserve','SizeOfHeapCommit','LoaderFlags','NumberOfRvaAndSizes','SuspiciousImportFunctions',
            'SuspiciousNameSection','SectionsLength','SectionMinEntropy','SectionMaxEntropy','SectionMinRawsize','SectionMaxRawsize','SectionMinVirtualsize',
            'SectionMaxVirtualsize','SectionMaxPhysical','SectionMinPhysical','SectionMaxVirtual','SectionMinVirtual','SectionMaxPointerData','SectionMinPointerData',
            'SectionMaxChar','SectionMainChar','DirectoryEntryImport','DirectoryEntryImportSize','DirectoryEntryExport','ImageDirectoryEntryExport','ImageDirectoryEntryImport',
            'ImageDirectoryEntryResource','ImageDirectoryEntryException','ImageDirectoryEntrySecurity']  # 생략 가능

x = dropped_df
y = df['Malware']

# 학습/테스트 분리
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

# 정규화
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x_train)
x_new = pd.DataFrame(x_scaled, columns=x.columns)

# 차원 축소
skpca = PCA(n_components=55)
x_pca = skpca.fit_transform(x_new)
print('Variance sum : ', skpca.explained_variance_.cumsum()[-1])

# 👉 LightGBM 모델 사용
model = LGBMClassifier(
    n_estimators=100,
    max_depth=16,
    random_state=0
)

model.fit(x_pca, y_train)

# 테스트 데이터 전처리
x_test_scaled = scaler.transform(x_test)
x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
x_test_pca = skpca.transform(x_new_test)

y_pred = model.predict(x_test_pca)
print(classification_report(y_pred, y_test))

# 파이프라인 구성
pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])

# 테스트용 파일 불러오기 및 예측
x_testing = df1.drop('Name', axis=1)
x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)

# 결과 DataFrame 생성 및 CSV 저장
result_df = pd.concat([df1['Name'], pd.DataFrame(y_testing_pred, columns=['Not Malware', 'Malware'])], axis=1)
result_df.to_csv('malware_files.csv', index=False)

# 결과 출력
print(result_df)
print("✅ 예측 결과가 'malware_files.csv'에 저장되었습니다.")
